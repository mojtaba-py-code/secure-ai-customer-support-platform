"""Two-factor authentication (TOTP): enrolment, verification, recovery codes and resets.

Flows
    enrol     POST /auth/mfa/setup   (password) -> secret + otpauth URI, shown once
              POST /auth/mfa/enable  (code)     -> recovery codes, shown once; every session is
                                                   revoked, so the next sign-in uses the code
    sign in   POST /auth/login                  -> {"mfa_required": true, "mfa_token": ...}
              POST /auth/mfa/verify  (token + code or recovery code) -> access + refresh tokens
    reset     an administrator clears a lost second factor (audited; never their own)

Security properties (each covered by tests):

* enrolment needs the password, so a stolen access token cannot bind an attacker's device;
* a login challenge is single use, short-lived and dies after a few wrong codes; wrong codes also
  count towards the account lockout, so the 10^6 code space cannot be brute-forced;
* each TOTP time step works once per account (atomic update) - an observed code cannot be
  replayed, not even by two concurrent requests;
* secrets are encrypted at rest; recovery codes are stored as SHA-256 digests;
* while the policy requires it, staff cannot switch the second factor off themselves.
"""

from __future__ import annotations

import time
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime

from sqlalchemy.ext.asyncio import AsyncSession

from aegis.core.config import Settings
from aegis.core.errors import AuthenticationFailed, Conflict, ValidationFailed
from aegis.core.time import Clock, utc_now
from aegis.domain.enums import STAFF_ROLES, AuditOutcome
from aegis.models import User
from aegis.observability import metrics
from aegis.repositories.identity import AuthSessionRepository, MfaRepository, UserRepository
from aegis.security.passwords import PasswordHasher
from aegis.security.principal import Principal
from aegis.security.totp import (
    generate_recovery_codes,
    generate_secret,
    hash_recovery_code,
    looks_like_recovery_code,
    provisioning_uri,
    verify_totp,
)
from aegis.services.audit import AuditService

MAX_CHALLENGE_ATTEMPTS = 5


@dataclass(frozen=True, slots=True)
class MfaSetup:
    secret: str
    otpauth_uri: str


@dataclass(frozen=True, slots=True)
class MfaStatus:
    enabled: bool
    enrollment_required: bool
    recovery_codes_remaining: int


async def clear_second_factor(user: User, repository: MfaRepository, now: datetime) -> None:
    """Remove every trace of a user's second factor (disable, administrator reset, erasure)."""
    user.mfa_secret = None
    user.mfa_pending_secret = None
    user.mfa_enabled_at = None
    user.mfa_last_step = None
    await repository.delete_recovery_codes(user.id)
    await repository.invalidate_challenges(user.id, now)


class MfaService:
    def __init__(
        self,
        session: AsyncSession,
        *,
        settings: Settings,
        hasher: PasswordHasher,
        audit: AuditService,
        clock: Clock = utc_now,
        epoch_seconds: Callable[[], float] = time.time,
    ) -> None:
        self._session = session
        self._settings = settings
        self._hasher = hasher
        self._audit = audit
        self._clock = clock
        self._epoch_seconds = epoch_seconds
        self._users = UserRepository(session)
        self._sessions = AuthSessionRepository(session)
        self._mfa = MfaRepository(session)

    def enrollment_required(self, user: User) -> bool:
        return (
            self._settings.mfa_required_for_staff
            and user.role in STAFF_ROLES
            and user.mfa_enabled_at is None
        )

    async def _user(self, principal: Principal) -> User:
        user = await self._users.get(principal.user_id)
        if user is None or not user.is_active:
            raise AuthenticationFailed
        return user

    async def status(self, principal: Principal) -> MfaStatus:
        user = await self._user(principal)
        remaining = (
            await self._mfa.count_unused_recovery_codes(user.id) if user.mfa_enabled_at else 0
        )
        return MfaStatus(
            enabled=user.mfa_enabled_at is not None,
            enrollment_required=self.enrollment_required(user),
            recovery_codes_remaining=remaining,
        )

    async def begin_setup(self, principal: Principal, *, password: str) -> MfaSetup:
        user = await self._user(principal)
        if user.mfa_enabled_at is not None:
            raise Conflict("Two-factor authentication is already on.")
        if not await self._hasher.verify_async(user.password_hash, password):
            await self._audit_failure(principal, "auth.mfa_setup", "bad_password")
            raise AuthenticationFailed("The password is incorrect.")
        secret = generate_secret()
        user.mfa_pending_secret = secret
        await self._session.commit()
        await self._audit.record("auth.mfa_setup", outcome=AuditOutcome.SUCCESS, actor=principal)
        return MfaSetup(
            secret=secret,
            otpauth_uri=provisioning_uri(
                secret, account=user.email, issuer=self._settings.app_name
            ),
        )

    async def enable(self, principal: Principal, *, code: str) -> list[str]:
        user = await self._user(principal)
        if user.mfa_enabled_at is not None:
            raise Conflict("Two-factor authentication is already on.")
        if user.mfa_pending_secret is None:
            raise Conflict("Start the two-factor setup first.")
        step = verify_totp(user.mfa_pending_secret, code, now=self._epoch_seconds())
        if step is None:
            await self._audit_failure(principal, "auth.mfa_enable", "bad_code")
            raise ValidationFailed(
                "The code is not valid. Check that your device's clock is correct and try again."
            )
        now = self._clock()
        user.mfa_secret = user.mfa_pending_secret
        user.mfa_pending_secret = None
        user.mfa_enabled_at = now
        user.mfa_last_step = step
        codes = generate_recovery_codes()
        await self._mfa.replace_recovery_codes(user.id, [hash_recovery_code(c) for c in codes], now)
        # Sessions opened with the password alone end now; the next sign-in needs the code.
        revoked = await self._sessions.revoke_all_for_user(user.id, reason="mfa_enabled", now=now)
        await self._session.commit()
        await self._audit.record(
            "auth.mfa_enable",
            outcome=AuditOutcome.SUCCESS,
            actor=principal,
            details={"revoked_sessions": revoked},
        )
        return codes

    async def disable(self, principal: Principal, *, password: str, code: str) -> None:
        user = await self._user(principal)
        if user.mfa_enabled_at is None:
            raise Conflict("Two-factor authentication is not on.")
        if self._settings.mfa_required_for_staff and user.role in STAFF_ROLES:
            raise Conflict(
                "Two-factor authentication is required for staff accounts. An administrator "
                "can reset it if you lost your device."
            )
        password_ok = await self._hasher.verify_async(user.password_hash, password)
        if not password_ok or await self.verify_second_factor(user, code) is None:
            await self._audit_failure(principal, "auth.mfa_disable", "bad_credentials")
            raise AuthenticationFailed("The password or the code is incorrect.")
        now = self._clock()
        await clear_second_factor(user, self._mfa, now)
        await self._sessions.revoke_all_for_user(
            user.id, reason="mfa_disabled", now=now, except_session=principal.session_id
        )
        await self._session.commit()
        await self._audit.record("auth.mfa_disable", outcome=AuditOutcome.SUCCESS, actor=principal)

    async def regenerate_recovery_codes(self, principal: Principal, *, code: str) -> list[str]:
        user = await self._user(principal)
        if user.mfa_enabled_at is None:
            raise Conflict("Two-factor authentication is not on.")
        if await self.verify_second_factor(user, code, allow_recovery=False) is None:
            await self._audit_failure(principal, "auth.mfa_recovery_codes", "bad_code")
            raise AuthenticationFailed("The code is incorrect.")
        now = self._clock()
        codes = generate_recovery_codes()
        await self._mfa.replace_recovery_codes(user.id, [hash_recovery_code(c) for c in codes], now)
        await self._session.commit()
        await self._audit.record(
            "auth.mfa_recovery_codes", outcome=AuditOutcome.SUCCESS, actor=principal
        )
        return codes

    async def verify_second_factor(
        self, user: User, code: str, *, allow_recovery: bool = True
    ) -> str | None:
        """``"totp"`` or ``"recovery_code"`` when ``code`` is valid (and now spent), else None."""
        if user.mfa_secret is None:
            return None
        step = verify_totp(
            user.mfa_secret, code, now=self._epoch_seconds(), last_step=user.mfa_last_step
        )
        if step is not None:
            if not await self._mfa.claim_step(user.id, step):
                return None  # this step was used concurrently: a replay
            user.mfa_last_step = step
            return "totp"
        if (
            allow_recovery
            and looks_like_recovery_code(code)
            and await self._mfa.use_recovery_code(user.id, hash_recovery_code(code), self._clock())
        ):
            metrics.security_event("mfa_recovery_code_used")
            return "recovery_code"
        return None

    async def _audit_failure(self, principal: Principal, action: str, reason: str) -> None:
        metrics.security_event("mfa_failed")
        await self._audit.record(
            action, outcome=AuditOutcome.FAILURE, actor=principal, details={"reason": reason}
        )
