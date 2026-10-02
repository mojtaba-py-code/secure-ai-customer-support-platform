"""Authorisation helpers used by every service method."""

from __future__ import annotations

import uuid

from aegis.core.errors import PermissionDenied
from aegis.observability import metrics
from aegis.security.principal import Principal
from aegis.security.rbac import Permission


def require(principal: Principal, permission: Permission) -> None:
    if not principal.has(permission):
        metrics.security_event("authorization_denied")
        raise PermissionDenied(log_message=f"{principal.role} lacks {permission}")


def customer_scope(principal: Principal, *, own: Permission, any_: Permission) -> uuid.UUID | None:
    """``None`` = may see every customer's records; a UUID = restricted to that customer.

    Raises when the caller holds neither permission, or holds only the "own" permission but is
    not linked to a customer record.
    """
    if principal.has(any_):
        return None
    if principal.has(own) and principal.customer_id is not None:
        return principal.customer_id
    metrics.security_event("authorization_denied")
    raise PermissionDenied(log_message=f"{principal.role} lacks {own}/{any_}")
