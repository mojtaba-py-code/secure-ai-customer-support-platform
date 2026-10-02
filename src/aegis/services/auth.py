"""Authentication: login, token refresh with rotation, logout, password change and reset.

Properties this service guarantees (each is covered by tests):

* **No account enumeration** - unknown e-mail, wrong password, locked and disabled accounts all
  produce the same error, and unknown accounts still pay for an Argon2 verification.
* **Brute-force resistance** - per-IP and per-account rate limits in the API layer, plus an
  account lockout after N consecutive failures.
* **Refresh-token rotation with theft detection** - each refresh token works once; presenting a
  spent token revokes the whole session (the legitimate user and the thief are both logged out).
* **Immediate revocation** - access tokens are checked against the session and user rows on
  every request, so logout, password change/reset and deactivation take effect at once.
* **Secure reset** - single-use, short-lived, hashed reset tokens delivered out of band; a reset
  revokes every session. The response never reveals whether the address is registered.
* **Two-factor authentication** - with TOTP enabled, a correct password yields only a short-lived,
  single-use challenge; tokens are issued after the code (see :mod:`aegis.services.mfa`). Wrong
  codes count towards the same lockout as wrong passwords.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import NoReturn

from sqlalchemy.ext.asyncio import AsyncSession

from aegis.core.config import Settings
from aegis.core.errors import AuthenticationFailed, ValidationFailed
from aegis.core.time import Clock, utc_now
from aegis.domain.enums import AuditOutcome
from aegis.models import AuthSession, MfaChallenge, PasswordResetToken, RefreshToken, User
from aegis.observability import metrics
from aegis.repositories.identity import AuthSessionRepository, MfaRepository, UserRepository
from aegis.security.crypto import fingerprint
from aegis.security.passwords import PasswordHasher, password_policy_problems
from aegis.security.principal import Principal
from aegis.security.tokens import TokenService, generate_opaque_token, hash_opaque_token
from aegis.services.audit import AuditService
from aegis.services.email import OutgoingEmail
from aegis.services.mfa import MAX_CHALLENGE_ATTEMPTS, MfaService

GENERIC_LOGIN_ERROR = "Invalid email or password."
INVALID_MFA = "The verification code is invalid or has expired. Please sign in again."
MAX_REFRESH_TOKEN_LENGTH = 256
SESSION_TOUCH_INTERVAL = timedelta(minutes=5)
MAX_RESET_REQUESTS_PER_HOUR = 3


@dataclass(frozen=True, slots=True)
class TokenPair:
    access_token: str
    access_expires_at: datetime
    refresh_token: str
    refresh_expires_at: datetime


@dataclass(frozen=True, slots=True)
class MfaChallengeIssued:
    """A correct password for an account with two-factor authentication: a code is still due."""

    token: str
    expires_at: datetime


class AuthService:
    def __init__(
        self,
        session: AsyncSession,
        *,
        settings: Settings,
        hasher: PasswordHasher,
        tokens: TokenService,
        audit: AuditService,
        mfa: MfaService,
        clock: Clock = utc_now,
    ) -> None:
        self._session = session
        self._settings = settings
        self._hasher = hasher
        self._tokens = tokens
        self._audit = audit
        self._mfa = mfa
        self._clock = clock
        self._users = UserRepository(session)
        self._sessions = AuthSessionRepository(session)
        self._mfa_state = MfaRepository(session)

    # --- login ------------------------------------------------------------------------------------
    async def login(
        self, email: str, password: str, *, ip: str | None, user_agent: str | None
    ) -> TokenPair | MfaChallengeIssued:
        normalized = email.strip().lower()
        now = self._clock()
        user = await self._users.get_by_email(normalized) if len(normalized) <= 254 else None
        if user is None:
            await self._hasher.verify_dummy_async(password)
            await self._fail_login(None, reason="unknown_account", email=normalized)
        if not user.is_active:
            await self._hasher.verify_dummy_async(password)
            await self._fail_login(user, reason="account_disabled")
        if user.locked_until is not None and user.locked_until > now:
            await self._hasher.verify_dummy_async(password)
            await self._fail_login(user, reason="account_locked")

        if not await self._hasher.verify_async(user.password_hash, password):
            user.failed_login_count += 1
            locked = user.failed_login_count >= self._settings.login_max_failed_attempts
            if locked:
                user.locked_until = now + timedelta(seconds=self._settings.login_lockout_seconds)
                user.failed_login_count = 0
                metrics.security_event("account_locked")
            await self._session.commit()
            await self._fail_login(user, reason="bad_password", locked=locked)

        if self._hasher.needs_rehash(user.password_hash):
            user.password_hash = await self._hasher.hash_async(password)
        if user.mfa_enabled_at is not None:
            # The failure counter is not reset yet: wrong codes keep counting towards the lockout.
            return await self._issue_challenge(user, ip=ip, now=now)
        user.failed_login_count = 0
        user.locked_until = None
        user.last_login_at = now
        pair = self._open_session(user, ip=ip, user_agent=user_agent, now=now)
        await self._session.commit()
        await self._audit.record(
            "auth.login",
            outcome=AuditOutcome.SUCCESS,
            actor_user_id=user.id,
            actor_role=user.role.value,
        )
        return pair

    async def _issue_challenge(
        self, user: User, *, ip: str | None, now: datetime
    ) -> MfaChallengeIssued:
        token = generate_opaque_token()
        expires_at = now + timedelta(seconds=self._settings.mfa_challenge_ttl_seconds)
        self._mfa_state.add_challenge(
            MfaChallenge(
                user_id=user.id,
                token_hash=hash_opaque_token(token),
                created_at=now,
                expires_at=expires_at,
                ip_address=(ip or "")[:45] or None,
            )
        )
        await self._session.commit()
        await self._audit.record(
            "auth.mfa_challenge",
            outcome=AuditOutcome.SUCCESS,
            actor_user_id=user.id,
            actor_role=user.role.value,
        )
        return MfaChallengeIssued(token=token, expires_at=expires_at)

    async def verify_mfa(
        self, mfa_token: str, code: str, *, ip: str | None, user_agent: str | None
    ) -> TokenPair:
        """Second login step: redeem the challenge with a TOTP code or a recovery code."""
        now = self._clock()
        if not mfa_token or len(mfa_token) > MAX_REFRESH_TOKEN_LENGTH:
            raise AuthenticationFailed(INVALID_MFA, log_message="mfa token missing or oversized")
        challenge = await self._mfa_state.get_challenge(hash_opaque_token(mfa_token))
        if challenge is None or challenge.used_at is not None or challenge.expires_at <= now:
            await self._fail_mfa(None, reason="invalid_challenge")
        user = await self._users.get(challenge.user_id)
        if user is None or not user.is_active or user.mfa_enabled_at is None:
            await self._fail_mfa(None, reason="invalid_user")
        if user.locked_until is not None and user.locked_until > now:
            await self._fail_mfa(user, reason="account_locked")

        method = await self._mfa.verify_second_factor(user, code)
        if method is None:
            await self._mfa_state.record_challenge_failure(
                challenge.id, max_attempts=MAX_CHALLENGE_ATTEMPTS, now=now
            )
            user.failed_login_count += 1
            locked = user.failed_login_count >= self._settings.login_max_failed_attempts
            if locked:
                user.locked_until = now + timedelta(seconds=self._settings.login_lockout_seconds)
                user.failed_login_count = 0
                await self._mfa_state.invalidate_challenges(user.id, now)
                metrics.security_event("account_locked")
            await self._session.commit()
            await self._fail_mfa(user, reason="bad_code", locked=locked)
        if not await self._mfa_state.redeem_challenge(challenge.id, now):
            await self._session.rollback()
            await self._fail_mfa(None, reason="challenge_reused")

        user.failed_login_count = 0
        user.locked_until = None
        user.last_login_at = now
        pair = self._open_session(user, ip=ip, user_agent=user_agent, now=now)
        await self._session.commit()
        await self._audit.record(
            "auth.login",
            outcome=AuditOutcome.SUCCESS,
            actor_user_id=user.id,
            actor_role=user.role.value,
            details={"mfa": method},
        )
        return pair

    async def _fail_mfa(self, user: User | None, *, reason: str, locked: bool = False) -> NoReturn:
        metrics.security_event("mfa_failed")
        await self._audit.record(
            "auth.mfa_verify",
            outcome=AuditOutcome.FAILURE,
            actor_user_id=user.id if user else None,
            actor_role=user.role.value if user else None,
            details={"reason": reason, "locked": locked},
        )
        raise AuthenticationFailed(INVALID_MFA, log_message=f"mfa verification failed: {reason}")

    async def _fail_login(
        self, user: User | None, *, reason: str, email: str | None = None, locked: bool = False
    ) -> NoReturn:
        metrics.security_event("login_failed")
        details: dict[str, object] = {"reason": reason, "locked": locked}
        if email is not None:
            details["email_fingerprint"] = fingerprint(email)
        await self._audit.record(
            "auth.login",
            outcome=AuditOutcome.FAILURE,
            actor_user_id=user.id if user else None,
            actor_role=user.role.value if user else None,
            details=details,
        )
        raise AuthenticationFailed(GENERIC_LOGIN_ERROR, log_message=f"login failed: {reason}")

    def _open_session(
        self, user: User, *, ip: str | None, user_agent: str | None, now: datetime
    ) -> TokenPair:
        auth_session = self._sessions.add_session(
            AuthSession(
                id=uuid.uuid4(),
                user_id=user.id,
                created_at=now,
                last_seen_at=now,
                expires_at=now + timedelta(seconds=self._settings.session_max_age_seconds),
                ip_address=(ip or "")[:45] or None,
                user_agent=(user_agent or "")[:200] or None,
            )
        )
        return self._issue_pair(user, auth_session, now=now)

    def _issue_pair(self, user: User, auth_session: AuthSession, *, now: datetime) -> TokenPair:
        refresh_plain = generate_opaque_token()
        refresh_expires = min(
            now + timedelta(seconds=self._settings.refresh_token_ttl_seconds),
            auth_session.expires_at,
        )
        self._sessions.add_refresh_token(
            RefreshToken(
                session_id=auth_session.id,
                token_hash=hash_opaque_token(refresh_plain),
                created_at=now,
                expires_at=refresh_expires,
            )
        )
        access, access_expires = self._tokens.issue_access_token(
            user_id=user.id, session_id=auth_session.id, role=user.role
        )
        return TokenPair(access, access_expires, refresh_plain, refresh_expires)

    # --- refresh ------------------------------------------------------------------------------------
    async def refresh(self, refresh_token: str) -> TokenPair:
        now = self._clock()
        if not refresh_token or len(refresh_token) > MAX_REFRESH_TOKEN_LENGTH:
            raise AuthenticationFailed(log_message="refresh token missing or oversized")
        found = await self._sessions.get_refresh_token(hash_opaque_token(refresh_token))
        if found is None:
            await self._audit.record(
                "auth.refresh", outcome=AuditOutcome.FAILURE, details={"reason": "unknown_token"}
            )
            raise AuthenticationFailed(log_message="unknown refresh token")
        token, auth_session = found

        if token.used_at is not None or not await self._sessions.mark_refresh_used(token.id, now):
            await self._sessions.revoke(auth_session.id, reason="refresh_token_reuse", now=now)
            await self._session.commit()
            metrics.security_event("refresh_token_reuse")
            await self._audit.record(
                "auth.refresh_reuse_detected",
                outcome=AuditOutcome.DENIED,
                actor_user_id=auth_session.user_id,
                resource_type="session",
                resource_id=auth_session.id,
            )
            raise AuthenticationFailed(
                "Your session has ended. Please sign in again.", log_message="refresh reuse"
            )

        if (
            auth_session.revoked_at is not None
            or auth_session.expires_at <= now
            or token.expires_at <= now
        ):
            await self._session.commit()
            raise AuthenticationFailed(
                "Your session has ended. Please sign in again.", log_message="session ended"
            )

        user = await self._users.get(auth_session.user_id)
        if user is None or not user.is_active:
            await self._sessions.revoke(auth_session.id, reason="user_inactive", now=now)
            await self._session.commit()
            raise AuthenticationFailed(log_message="refresh for inactive user")

        auth_session.last_seen_at = now
        pair = self._issue_pair(user, auth_session, now=now)
        await self._session.commit()
        return pair

    # --- request authentication ------------------------------------------------------------------------
    async def authenticate(self, access_token: str) -> Principal:
        claims = self._tokens.decode_access_token(access_token)
        now = self._clock()
        found = await self._users.get_authenticated(claims.user_id, claims.session_id, now)
        if found is None:
            raise AuthenticationFailed(
                "Your session has ended. Please sign in again.", log_message="session invalid"
            )
        user, auth_session = found
        if now - auth_session.last_seen_at > SESSION_TOUCH_INTERVAL:
            await self._sessions.touch(auth_session.id, now)
            await self._session.commit()
        return Principal(
            user_id=user.id,
            role=user.role,  # the current role from the database, not the one in the token
            session_id=auth_session.id,
            customer_id=user.customer_id,
            display_name=user.display_name,
            mfa_enabled=user.mfa_enabled_at is not None,
            mfa_enrollment_required=self._mfa.enrollment_required(user),
        )

    # --- logout ------------------------------------------------------------------------------------------
    async def logout(self, principal: Principal) -> None:
        await self._sessions.revoke(principal.session_id, reason="logout", now=self._clock())
        await self._session.commit()
        await self._audit.record("auth.logout", outcome=AuditOutcome.SUCCESS, actor=principal)

    async def logout_all(self, principal: Principal) -> int:
        count = await self._sessions.revoke_all_for_user(
            principal.user_id, reason="logout_all", now=self._clock()
        )
        await self._session.commit()
        await self._audit.record(
            "auth.logout_all",
            outcome=AuditOutcome.SUCCESS,
            actor=principal,
            details={"sessions": count},
        )
        return count

    # --- passwords ------------------------------------------------------------------------------------------
    async def change_password(
        self, principal: Principal, *, current_password: str, new_password: str
    ) -> None:
        user = await self._users.get(principal.user_id)
        if user is None:
            raise AuthenticationFailed
        if not await self._hasher.verify_async(user.password_hash, current_password):
            await self._audit.record(
                "auth.password_change",
                outcome=AuditOutcome.FAILURE,
                actor=principal,
                details={"reason": "bad_current"},
            )
            raise AuthenticationFailed("The current password is incorrect.")
        if new_password == current_password:
            raise ValidationFailed("The new password must be different from the current one.")
        self._enforce_policy(new_password, email=user.email)
        now = self._clock()
        user.password_hash = await self._hasher.hash_async(new_password)
        user.password_changed_at = now
        await self._sessions.revoke_all_for_user(
            user.id, reason="password_changed", now=now, except_session=principal.session_id
        )
        await self._sessions.invalidate_reset_tokens(user.id, now)
        await self._session.commit()
        await self._audit.record(
            "auth.password_change", outcome=AuditOutcome.SUCCESS, actor=principal
        )

    def _enforce_policy(self, password: str, *, email: str) -> None:
        problems = password_policy_problems(
            password, min_length=self._settings.password_min_length, email=email
        )
        if problems:
            raise ValidationFailed(
                "The password " + "; ".join(problems) + ".", details={"problems": problems}
            )

    async def request_password_reset(self, email: str) -> OutgoingEmail | None:
        """Create a reset token if the account exists; the caller sends the e-mail out of band.

        The HTTP response is identical either way (202) so the endpoint cannot be used to probe
        which addresses are registered; per-address requests are capped.
        """
        normalized = email.strip().lower()
        now = self._clock()
        user = await self._users.get_by_email(normalized) if len(normalized) <= 254 else None
        if user is None or not user.is_active:
            await self._audit.record(
                "auth.password_reset_request",
                outcome=AuditOutcome.FAILURE,
                details={
                    "reason": "unknown_or_inactive",
                    "email_fingerprint": fingerprint(normalized),
                },
            )
            return None
        recent = await self._sessions.count_recent_reset_requests(user.id, now - timedelta(hours=1))
        if recent >= MAX_RESET_REQUESTS_PER_HOUR:
            await self._audit.record(
                "auth.password_reset_request",
                outcome=AuditOutcome.DENIED,
                actor_user_id=user.id,
                details={"reason": "too_many_requests"},
            )
            return None
        token = generate_opaque_token()
        self._sessions.add_reset_token(
            PasswordResetToken(
                user_id=user.id,
                token_hash=hash_opaque_token(token),
                created_at=now,
                expires_at=now + timedelta(seconds=self._settings.password_reset_ttl_seconds),
            )
        )
        await self._session.commit()
        await self._audit.record(
            "auth.password_reset_request", outcome=AuditOutcome.SUCCESS, actor_user_id=user.id
        )
        minutes = self._settings.password_reset_ttl_seconds // 60
        # The token travels in the URL *fragment*: browsers never send it to a server, so it does
        # not end up in access logs or Referer headers.
        link = f"{self._settings.password_reset_url}#token={token}"
        return OutgoingEmail(
            to=user.email,
            subject=f"{self._settings.company_name}: reset your password",
            body=(
                f"Hello {user.display_name},\n\n"
                f"Use this link within {minutes} minutes to choose a new password:\n{link}\n\n"
                "If you did not ask for this, you can ignore this message; your password is unchanged.\n"
                "We will never ask you for your password by e-mail, chat or phone.\n"
            ),
        )

    async def confirm_password_reset(self, token: str, new_password: str) -> None:
        now = self._clock()
        invalid = ValidationFailed("This password reset link is invalid or has expired.")
        if not token or len(token) > MAX_REFRESH_TOKEN_LENGTH:
            raise invalid
        record = await self._sessions.get_reset_token(hash_opaque_token(token))
        if record is None or record.used_at is not None or record.expires_at <= now:
            await self._audit.record(
                "auth.password_reset",
                outcome=AuditOutcome.FAILURE,
                details={"reason": "invalid_token"},
            )
            raise invalid
        user = await self._users.get(record.user_id)
        if user is None or not user.is_active:
            raise invalid
        self._enforce_policy(new_password, email=user.email)
        if not await self._sessions.mark_reset_used(record.id, now):
            raise invalid
        user.password_hash = await self._hasher.hash_async(new_password)
        user.password_changed_at = now
        user.failed_login_count = 0
        user.locked_until = None
        await self._sessions.revoke_all_for_user(user.id, reason="password_reset", now=now)
        await self._sessions.invalidate_reset_tokens(user.id, now)
        await self._session.commit()
        await self._audit.record(
            "auth.password_reset",
            outcome=AuditOutcome.SUCCESS,
            actor_user_id=user.id,
            actor_role=user.role.value,
        )
