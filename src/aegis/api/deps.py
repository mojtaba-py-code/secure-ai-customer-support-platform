"""Request dependencies: container, session, services, authentication, RBAC, rate limits."""

from __future__ import annotations

from collections.abc import AsyncIterator, Awaitable, Callable
from dataclasses import dataclass
from typing import Annotated, Any, cast

from fastapi import Depends, Header, Query, Request
from fastapi.dependencies.models import Dependant
from fastapi.exceptions import RequestValidationError
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy.ext.asyncio import AsyncSession

from aegis.bootstrap import AppContainer, RequestServices
from aegis.core.context import user_id_var
from aegis.core.errors import AuthenticationFailed, PermissionDenied, RateLimited
from aegis.kv.rate_limit import RateLimitPolicy
from aegis.observability import metrics
from aegis.security.principal import Principal
from aegis.security.rbac import Permission
from aegis.services.idempotency import validate_idempotency_key


def get_container(request: Request) -> AppContainer:
    return cast(AppContainer, request.app.state.container)


ContainerDep = Annotated[AppContainer, Depends(get_container)]


async def get_session(container: ContainerDep) -> AsyncIterator[AsyncSession]:
    async with container.sessionmaker() as session:
        try:
            yield session
        except Exception:
            await session.rollback()
            raise


SessionDep = Annotated[AsyncSession, Depends(get_session)]


def get_services(container: ContainerDep, session: SessionDep) -> RequestServices:
    return RequestServices(container, session)


ServicesDep = Annotated[RequestServices, Depends(get_services)]


def client_ip(request: Request) -> str:
    state = request.scope.get("state") or {}
    ip = state.get("client_ip") if isinstance(state, dict) else None
    if ip:
        return str(ip)
    return request.client.host if request.client else "unknown"


ClientIpDep = Annotated[str, Depends(client_ip)]


async def enforce_rate_limit(
    container: AppContainer, policy: RateLimitPolicy, identity: str
) -> None:
    decision = await container.rate_limiter.hit(policy, identity)
    if not decision.allowed:
        metrics.RATE_LIMITED.labels(policy=policy.name).inc()
        raise RateLimited(decision.retry_after_seconds)


_bearer = HTTPBearer(auto_error=False, description="Access token from /api/v1/auth/login")


async def get_principal(
    container: ContainerDep,
    services: ServicesDep,
    credentials: Annotated[HTTPAuthorizationCredentials | None, Depends(_bearer)],
) -> Principal:
    if credentials is None or credentials.scheme.lower() != "bearer" or not credentials.credentials:
        raise AuthenticationFailed("Authentication required.")
    principal = await services.auth.authenticate(credentials.credentials)
    user_id_var.set(str(principal.user_id))
    await enforce_rate_limit(container, container.rate_limits.api_user, f"user:{principal.user_id}")
    return principal


PrincipalDep = Annotated[Principal, Depends(get_principal)]


@dataclass(frozen=True, slots=True)
class PermissionRequirement:
    permission: Permission
    admin_rate_limit: bool


#: Dependency -> the requirement it enforces. Lets scripts/generate_docs.py document every
#: route's permission from the code itself instead of from a hand-maintained list.
_REQUIREMENTS: dict[Callable[..., Any], PermissionRequirement] = {}


def requirement_of(dependency: Callable[..., Any]) -> PermissionRequirement | None:
    return _REQUIREMENTS.get(dependency)


def require(permission: Permission) -> Callable[[Principal], Awaitable[Principal]]:
    """Dependency factory: the caller must hold ``permission`` (checked on the server)."""

    async def dependency(principal: PrincipalDep) -> Principal:
        if not principal.has(permission):
            metrics.security_event("authorization_denied")
            raise PermissionDenied(log_message=f"{principal.role} lacks {permission}")
        return principal

    _REQUIREMENTS[dependency] = PermissionRequirement(permission, admin_rate_limit=False)
    return dependency


def require_admin(
    permission: Permission,
) -> Callable[[AppContainer, Principal], Awaitable[Principal]]:
    """Like :func:`require`, plus the stricter administrative rate limit."""

    async def dependency(container: ContainerDep, principal: PrincipalDep) -> Principal:
        if not principal.has(permission):
            metrics.security_event("authorization_denied")
            raise PermissionDenied(log_message=f"{principal.role} lacks {permission}")
        await enforce_rate_limit(
            container, container.rate_limits.admin, f"admin:{principal.user_id}"
        )
        return principal

    _REQUIREMENTS[dependency] = PermissionRequirement(permission, admin_rate_limit=True)
    return dependency


async def ip_rate_limit(container: ContainerDep, ip: ClientIpDep) -> None:
    await enforce_rate_limit(container, container.rate_limits.api_ip, f"ip:{ip}")


def declared_query_parameters(dependant: Dependant) -> frozenset[str]:
    """The query parameter names an endpoint accepts, including those of its dependencies.

    Walked per request: a handful of nodes, and FastAPI's ``Dependant`` is not hashable.
    """
    names: set[str] = set()
    pending = [dependant]
    while pending:
        current = pending.pop()
        names.update(field.alias for field in current.query_params)
        pending.extend(current.dependencies)
    return frozenset(names)


async def reject_unknown_query_parameters(request: Request) -> None:
    """Query strings are validated like bodies (``extra="forbid"``): an undeclared parameter is a 422.

    A misspelt filter (``?stauts=open``) would otherwise be ignored silently and widen the result.
    The rejected names are not echoed: like submitted values, they are the client's input.
    """
    dependant = getattr(request.scope.get("route"), "dependant", None)
    if not isinstance(dependant, Dependant):
        return
    declared = declared_query_parameters(dependant)
    if any(name not in declared for name in request.query_params):
        raise RequestValidationError(
            [{"loc": ("query",), "msg": "Unknown query parameter.", "type": "extra_forbidden"}]
        )


def idempotency_key(
    key: Annotated[str | None, Header(alias="Idempotency-Key", max_length=200)] = None,
) -> str | None:
    return validate_idempotency_key(key)


IdempotencyKeyDep = Annotated[str | None, Depends(idempotency_key)]
Limit = Annotated[int, Query(ge=1, le=100)]
Offset = Annotated[int, Query(ge=0, le=10_000)]
