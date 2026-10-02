"""The authenticated caller, as established by the server (never by the client or the model)."""

from __future__ import annotations

import uuid
from dataclasses import dataclass

from aegis.domain.enums import Role
from aegis.security.rbac import Permission, has_permission


@dataclass(frozen=True, slots=True)
class Principal:
    user_id: uuid.UUID
    role: Role
    session_id: uuid.UUID
    customer_id: uuid.UUID | None
    display_name: str
    mfa_enabled: bool = False
    #: Two-factor authentication is required for this account but not set up yet. Until it is,
    #: the principal holds no permission at all - it can only enrol, change its password, look
    #: at itself and sign out (routes that need authentication but no permission).
    mfa_enrollment_required: bool = False

    def has(self, permission: Permission) -> bool:
        if self.mfa_enrollment_required:
            return False
        return has_permission(self.role, permission)

    @property
    def is_customer(self) -> bool:
        return self.role is Role.CUSTOMER
