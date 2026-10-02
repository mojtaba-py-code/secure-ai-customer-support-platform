"""Security audit trail.

Events are written in their own short transaction so that a failed business operation (which
rolls back) still leaves its audit record - failures and denials are exactly what an
investigator needs. Details are scrubbed (no secrets, no message content) and size-capped.
"""

from __future__ import annotations

import logging
import uuid
from datetime import datetime
from typing import Any

from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from aegis.core.context import client_ip_var, request_id_var
from aegis.core.time import utc_now
from aegis.domain.enums import AuditOutcome
from aegis.models import AuditEvent
from aegis.repositories.operations import AuditRepository
from aegis.security.principal import Principal
from aegis.security.rbac import Permission
from aegis.security.redaction import redact
from aegis.services.authz import require

logger = logging.getLogger(__name__)

_FORBIDDEN_DETAIL_KEYS = ("password", "token", "secret", "content", "text", "authorization", "card")


def _sanitize(details: dict[str, Any] | None) -> dict[str, Any]:
    clean: dict[str, Any] = {}
    for key, value in list((details or {}).items())[:30]:
        name = str(key)[:60]
        if any(part in name.lower() for part in _FORBIDDEN_DETAIL_KEYS):
            continue
        if isinstance(value, str):
            clean[name] = redact(value[:300]).text
        elif isinstance(value, int | float | bool) or value is None:
            clean[name] = value
        elif isinstance(value, list | tuple):
            clean[name] = [redact(str(v)[:100]).text for v in list(value)[:20]]
        else:
            clean[name] = redact(str(value)[:300]).text
    return clean


class AuditService:
    def __init__(self, sessionmaker: async_sessionmaker[AsyncSession]) -> None:
        self._sessionmaker = sessionmaker

    async def record(
        self,
        action: str,
        *,
        outcome: AuditOutcome,
        actor: Principal | None = None,
        actor_user_id: uuid.UUID | None = None,
        actor_role: str | None = None,
        resource_type: str | None = None,
        resource_id: str | uuid.UUID | None = None,
        details: dict[str, Any] | None = None,
    ) -> None:
        event = AuditEvent(
            occurred_at=utc_now(),
            actor_user_id=actor.user_id if actor else actor_user_id,
            actor_role=actor.role.value if actor else actor_role,
            action=action[:80],
            resource_type=resource_type,
            resource_id=str(resource_id)[:64] if resource_id is not None else None,
            outcome=outcome,
            request_id=request_id_var.get(),
            ip_address=client_ip_var.get(),
            details=_sanitize(details),
        )
        try:
            async with self._sessionmaker() as session:
                AuditRepository(session).add(event)
                await session.commit()
        except Exception:  # auditing must never take the request down with it
            logger.exception(
                "failed to write audit event",
                extra={"event": "audit.write_failed", "action": action},
            )
        log = (
            logger.warning if outcome in (AuditOutcome.DENIED, AuditOutcome.ERROR) else logger.info
        )
        log(
            "audit",
            extra={
                "event": "audit",
                "action": action,
                "outcome": outcome.value,
                "resource_type": resource_type,
                "resource_id": event.resource_id,
            },
        )

    async def list_events(
        self,
        principal: Principal,
        *,
        action_prefix: str | None,
        actor_user_id: uuid.UUID | None,
        outcome: AuditOutcome | None,
        since: datetime | None,
        limit: int,
        offset: int,
    ) -> list[AuditEvent]:
        require(principal, Permission.AUDIT_READ)
        async with self._sessionmaker() as session:
            return await AuditRepository(session).list_events(
                action_prefix=action_prefix,
                actor_user_id=actor_user_id,
                outcome=outcome,
                since=since,
                limit=limit,
                offset=offset,
            )
