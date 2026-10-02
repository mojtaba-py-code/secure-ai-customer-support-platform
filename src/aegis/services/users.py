"""Administration of staff accounts.

Customer identities are provisioned from the commerce system (the seed data plays that role in
the demo); administrators create and manage *staff* accounts. Safety rails: an administrator
cannot demote, deactivate or lock out their own account, deactivation revokes every session
immediately, and every change is audited.
"""

from __future__ import annotations

import uuid

from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from aegis.core.config import Settings
from aegis.core.errors import Conflict, NotFound, ValidationFailed
from aegis.core.time import Clock, utc_now
from aegis.domain.enums import STAFF_ROLES, AuditOutcome, Role
from aegis.models import User
from aegis.repositories.identity import AuthSessionRepository, MfaRepository, UserRepository
from aegis.security.passwords import PasswordHasher, password_policy_problems
from aegis.security.principal import Principal
from aegis.security.rbac import Permission
from aegis.services.audit import AuditService
from aegis.services.authz import require
from aegis.services.mfa import clear_second_factor


class UserAdminService:
    def __init__(
        self,
        session: AsyncSession,
        *,
        settings: Settings,
        hasher: PasswordHasher,
        audit: AuditService,
        clock: Clock = utc_now,
    ) -> None:
        self._session = session
        self._settings = settings
        self._hasher = hasher
        self._audit = audit
        self._clock = clock
        self._users = UserRepository(session)
        self._sessions = AuthSessionRepository(session)
        self._mfa = MfaRepository(session)

    async def create_staff(
        self, principal: Principal, *, email: str, display_name: str, role: Role, password: str
    ) -> User:
        require(principal, Permission.USER_MANAGE)
        if role not in STAFF_ROLES:
            raise ValidationFailed("Only staff accounts can be created here.")
        normalized = email.strip().lower()
        problems = password_policy_problems(
            password, min_length=self._settings.password_min_length, email=normalized
        )
        if problems:
            raise ValidationFailed(
                "The password " + "; ".join(problems) + ".", details={"problems": problems}
            )
        user = User(
            email=normalized,
            password_hash=await self._hasher.hash_async(password),
            role=role,
            display_name=display_name.strip(),
            customer_id=None,
            is_active=True,
            password_changed_at=self._clock(),
        )
        self._users.add(user)
        try:
            await self._session.commit()
        except IntegrityError as exc:
            await self._session.rollback()
            raise Conflict("An account with this email already exists.") from exc
        await self._audit.record(
            "admin.user_create",
            outcome=AuditOutcome.SUCCESS,
            actor=principal,
            resource_type="user",
            resource_id=user.id,
            details={"role": role.value},
        )
        return user

    async def list_users(
        self, principal: Principal, *, role: Role | None, limit: int, offset: int
    ) -> list[User]:
        require(principal, Permission.USER_MANAGE)
        return await self._users.list_users(role=role, limit=limit, offset=offset)

    async def update(
        self,
        principal: Principal,
        user_id: uuid.UUID,
        *,
        role: Role | None = None,
        is_active: bool | None = None,
    ) -> User:
        require(principal, Permission.USER_MANAGE)
        user = await self._users.get(user_id)
        if user is None:
            raise NotFound
        if user.id == principal.user_id and (role not in (None, user.role) or is_active is False):
            raise Conflict("You cannot change your own role or deactivate your own account.")
        changes: dict[str, object] = {}
        if role is not None and role != user.role:
            if (user.role is Role.CUSTOMER) != (role is Role.CUSTOMER):
                raise ValidationFailed(
                    "Customer accounts cannot be converted to staff accounts or back."
                )
            changes["role"] = f"{user.role.value}->{role.value}"
            user.role = role
        if is_active is not None and is_active != user.is_active:
            changes["is_active"] = is_active
            user.is_active = is_active
            if not is_active:
                await self._sessions.revoke_all_for_user(
                    user.id, reason="deactivated", now=self._clock()
                )
        await self._session.commit()
        if changes:
            await self._audit.record(
                "admin.user_update",
                outcome=AuditOutcome.SUCCESS,
                actor=principal,
                resource_type="user",
                resource_id=user.id,
                details=changes,
            )
        return user

    async def unlock(self, principal: Principal, user_id: uuid.UUID) -> User:
        require(principal, Permission.USER_MANAGE)
        user = await self._users.get(user_id)
        if user is None:
            raise NotFound
        user.locked_until = None
        user.failed_login_count = 0
        await self._session.commit()
        await self._audit.record(
            "admin.user_unlock",
            outcome=AuditOutcome.SUCCESS,
            actor=principal,
            resource_type="user",
            resource_id=user.id,
        )
        return user

    async def revoke_sessions(self, principal: Principal, user_id: uuid.UUID) -> int:
        require(principal, Permission.USER_MANAGE)
        user = await self._users.get(user_id)
        if user is None:
            raise NotFound
        count = await self._sessions.revoke_all_for_user(
            user.id, reason="admin_revoked", now=self._clock()
        )
        await self._session.commit()
        await self._audit.record(
            "admin.user_revoke_sessions",
            outcome=AuditOutcome.SUCCESS,
            actor=principal,
            resource_type="user",
            resource_id=user.id,
            details={"sessions": count},
        )
        return count

    async def reset_mfa(self, principal: Principal, user_id: uuid.UUID) -> User:
        """Clear a lost second factor. The user signs in with the password and enrols again."""
        require(principal, Permission.USER_MANAGE)
        user = await self._users.get(user_id)
        if user is None:
            raise NotFound
        if user.id == principal.user_id:
            raise Conflict("You cannot reset your own two-factor authentication.")
        if user.mfa_enabled_at is None and user.mfa_pending_secret is None:
            raise Conflict("Two-factor authentication is not set up for this account.")
        now = self._clock()
        await clear_second_factor(user, self._mfa, now)
        revoked = await self._sessions.revoke_all_for_user(user.id, reason="mfa_reset", now=now)
        await self._session.commit()
        await self._audit.record(
            "admin.user_reset_mfa",
            outcome=AuditOutcome.SUCCESS,
            actor=principal,
            resource_type="user",
            resource_id=user.id,
            details={"revoked_sessions": revoked},
        )
        return user
