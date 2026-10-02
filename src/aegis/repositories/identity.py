"""Users, sessions, refresh tokens and password-reset tokens."""

from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import delete, func, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from aegis.domain.enums import Role
from aegis.models import (
    AuthSession,
    MfaChallenge,
    MfaRecoveryCode,
    PasswordResetToken,
    RefreshToken,
    User,
)
from aegis.repositories.common import affected_rows, clamp_page


class UserRepository:
    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def get(self, user_id: uuid.UUID) -> User | None:
        return await self._session.get(User, user_id)

    async def get_by_email(self, email: str) -> User | None:
        result = await self._session.execute(
            select(User).where(User.email == email.strip().lower())
        )
        return result.scalar_one_or_none()

    async def get_authenticated(
        self, user_id: uuid.UUID, session_id: uuid.UUID, now: datetime
    ) -> tuple[User, AuthSession] | None:
        """The user and session behind an access token, only if both are still valid."""
        stmt = (
            select(User, AuthSession)
            .join(AuthSession, AuthSession.user_id == User.id)
            .where(
                User.id == user_id,
                User.is_active.is_(True),
                AuthSession.id == session_id,
                AuthSession.revoked_at.is_(None),
                AuthSession.expires_at > now,
            )
        )
        row = (await self._session.execute(stmt)).first()
        return None if row is None else (row[0], row[1])

    def add(self, user: User) -> User:
        self._session.add(user)
        return user

    async def list_users(self, *, role: Role | None, limit: int, offset: int) -> list[User]:
        limit, offset = clamp_page(limit, offset)
        stmt = select(User).order_by(User.created_at.desc(), User.id).limit(limit).offset(offset)
        if role is not None:
            stmt = stmt.where(User.role == role)
        return list((await self._session.execute(stmt)).scalars())


class AuthSessionRepository:
    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    def add_session(self, auth_session: AuthSession) -> AuthSession:
        self._session.add(auth_session)
        return auth_session

    async def get_session(self, session_id: uuid.UUID) -> AuthSession | None:
        return await self._session.get(AuthSession, session_id)

    async def touch(self, session_id: uuid.UUID, now: datetime) -> None:
        await self._session.execute(
            update(AuthSession).where(AuthSession.id == session_id).values(last_seen_at=now)
        )

    async def revoke(self, session_id: uuid.UUID, *, reason: str, now: datetime) -> bool:
        result = await self._session.execute(
            update(AuthSession)
            .where(AuthSession.id == session_id, AuthSession.revoked_at.is_(None))
            .values(revoked_at=now, revoked_reason=reason)
        )
        return affected_rows(result) > 0

    async def revoke_all_for_user(
        self,
        user_id: uuid.UUID,
        *,
        reason: str,
        now: datetime,
        except_session: uuid.UUID | None = None,
    ) -> int:
        stmt = (
            update(AuthSession)
            .where(AuthSession.user_id == user_id, AuthSession.revoked_at.is_(None))
            .values(revoked_at=now, revoked_reason=reason)
        )
        if except_session is not None:
            stmt = stmt.where(AuthSession.id != except_session)
        result = await self._session.execute(stmt)
        return affected_rows(result)

    def add_refresh_token(self, token: RefreshToken) -> RefreshToken:
        self._session.add(token)
        return token

    async def get_refresh_token(self, token_hash: str) -> tuple[RefreshToken, AuthSession] | None:
        stmt = (
            select(RefreshToken, AuthSession)
            .join(AuthSession, AuthSession.id == RefreshToken.session_id)
            .where(RefreshToken.token_hash == token_hash)
        )
        row = (await self._session.execute(stmt)).first()
        return None if row is None else (row[0], row[1])

    async def mark_refresh_used(self, token_id: uuid.UUID, now: datetime) -> bool:
        """Atomically spend a refresh token; False means it was already used (possible theft)."""
        result = await self._session.execute(
            update(RefreshToken)
            .where(RefreshToken.id == token_id, RefreshToken.used_at.is_(None))
            .values(used_at=now)
        )
        return affected_rows(result) == 1

    def add_reset_token(self, token: PasswordResetToken) -> PasswordResetToken:
        self._session.add(token)
        return token

    async def get_reset_token(self, token_hash: str) -> PasswordResetToken | None:
        result = await self._session.execute(
            select(PasswordResetToken).where(PasswordResetToken.token_hash == token_hash)
        )
        return result.scalar_one_or_none()

    async def mark_reset_used(self, token_id: uuid.UUID, now: datetime) -> bool:
        result = await self._session.execute(
            update(PasswordResetToken)
            .where(PasswordResetToken.id == token_id, PasswordResetToken.used_at.is_(None))
            .values(used_at=now)
        )
        return affected_rows(result) == 1

    async def invalidate_reset_tokens(self, user_id: uuid.UUID, now: datetime) -> None:
        await self._session.execute(
            update(PasswordResetToken)
            .where(PasswordResetToken.user_id == user_id, PasswordResetToken.used_at.is_(None))
            .values(used_at=now)
        )

    async def purge_expired(self, *, before: datetime) -> int:
        """Data retention: drop spent/expired tokens and sessions that ended before ``before``."""
        removed = 0
        for stmt in (
            delete(RefreshToken).where(RefreshToken.expires_at < before),
            delete(PasswordResetToken).where(PasswordResetToken.expires_at < before),
            delete(MfaChallenge).where(MfaChallenge.expires_at < before),
            delete(AuthSession).where(AuthSession.expires_at < before),
            delete(AuthSession).where(
                AuthSession.revoked_at.is_not(None), AuthSession.revoked_at < before
            ),
        ):
            result = await self._session.execute(stmt)
            removed += affected_rows(result)
        return removed

    async def count_recent_reset_requests(self, user_id: uuid.UUID, since: datetime) -> int:
        stmt = (
            select(func.count())
            .select_from(PasswordResetToken)
            .where(PasswordResetToken.user_id == user_id, PasswordResetToken.created_at >= since)
        )
        return int((await self._session.execute(stmt)).scalar_one())


class MfaRepository:
    """Second-factor state. Every "use once" rule is an atomic conditional UPDATE."""

    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    def add_challenge(self, challenge: MfaChallenge) -> MfaChallenge:
        self._session.add(challenge)
        return challenge

    async def get_challenge(self, token_hash: str) -> MfaChallenge | None:
        result = await self._session.execute(
            select(MfaChallenge).where(MfaChallenge.token_hash == token_hash)
        )
        return result.scalar_one_or_none()

    async def redeem_challenge(self, challenge_id: uuid.UUID, now: datetime) -> bool:
        """Spend a challenge; False when it was already used (a concurrent or replayed request)."""
        result = await self._session.execute(
            update(MfaChallenge)
            .where(MfaChallenge.id == challenge_id, MfaChallenge.used_at.is_(None))
            .values(used_at=now)
        )
        return affected_rows(result) == 1

    async def record_challenge_failure(
        self, challenge_id: uuid.UUID, *, max_attempts: int, now: datetime
    ) -> None:
        await self._session.execute(
            update(MfaChallenge)
            .where(MfaChallenge.id == challenge_id)
            .values(failed_attempts=MfaChallenge.failed_attempts + 1)
        )
        await self._session.execute(
            update(MfaChallenge)
            .where(
                MfaChallenge.id == challenge_id,
                MfaChallenge.failed_attempts >= max_attempts,
                MfaChallenge.used_at.is_(None),
            )
            .values(used_at=now)
        )

    async def invalidate_challenges(self, user_id: uuid.UUID, now: datetime) -> None:
        await self._session.execute(
            update(MfaChallenge)
            .where(MfaChallenge.user_id == user_id, MfaChallenge.used_at.is_(None))
            .values(used_at=now)
        )

    async def claim_step(self, user_id: uuid.UUID, step: int) -> bool:
        """Record a used TOTP step; False when this or a later step was already used (replay)."""
        result = await self._session.execute(
            update(User)
            .where(
                User.id == user_id,
                (User.mfa_last_step.is_(None)) | (User.mfa_last_step < step),
            )
            .values(mfa_last_step=step)
        )
        return affected_rows(result) == 1

    async def replace_recovery_codes(
        self, user_id: uuid.UUID, code_hashes: list[str], now: datetime
    ) -> None:
        await self.delete_recovery_codes(user_id)
        for code_hash in code_hashes:
            self._session.add(MfaRecoveryCode(user_id=user_id, code_hash=code_hash, created_at=now))

    async def use_recovery_code(self, user_id: uuid.UUID, code_hash: str, now: datetime) -> bool:
        result = await self._session.execute(
            update(MfaRecoveryCode)
            .where(
                MfaRecoveryCode.user_id == user_id,
                MfaRecoveryCode.code_hash == code_hash,
                MfaRecoveryCode.used_at.is_(None),
            )
            .values(used_at=now)
        )
        return affected_rows(result) == 1

    async def count_unused_recovery_codes(self, user_id: uuid.UUID) -> int:
        stmt = (
            select(func.count())
            .select_from(MfaRecoveryCode)
            .where(MfaRecoveryCode.user_id == user_id, MfaRecoveryCode.used_at.is_(None))
        )
        return int((await self._session.execute(stmt)).scalar_one())

    async def delete_recovery_codes(self, user_id: uuid.UUID) -> None:
        await self._session.execute(
            delete(MfaRecoveryCode).where(MfaRecoveryCode.user_id == user_id)
        )
