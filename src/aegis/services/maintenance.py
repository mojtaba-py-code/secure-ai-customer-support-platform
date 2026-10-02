"""Periodic housekeeping run by the worker: expiry and data retention."""

from __future__ import annotations

from datetime import timedelta

from sqlalchemy.ext.asyncio import AsyncSession

from aegis.core.time import Clock, utc_now
from aegis.repositories.identity import AuthSessionRepository
from aegis.repositories.operations import IdempotencyRepository
from aegis.repositories.support import PendingActionRepository
from aegis.services.privacy import PrivacyService

TOKEN_RETENTION = timedelta(days=30)


class MaintenanceService:
    def __init__(
        self,
        session: AsyncSession,
        *,
        privacy: PrivacyService,
        conversation_retention_days: int,
        clock: Clock = utc_now,
    ) -> None:
        self._session = session
        self._privacy = privacy
        self._retention_days = conversation_retention_days
        self._clock = clock

    async def run(self) -> dict[str, int]:
        now = self._clock()
        expired_actions = await PendingActionRepository(self._session).expire_stale(now)
        purged_keys = await IdempotencyRepository(self._session).purge_expired(now)
        purged_auth = await AuthSessionRepository(self._session).purge_expired(
            before=now - TOKEN_RETENTION
        )
        expired_conversations = await self._privacy.expire_conversations(
            retention_days=self._retention_days
        )
        await self._session.commit()
        return {
            "expired_actions": expired_actions,
            "purged_idempotency_keys": purged_keys,
            "purged_auth_records": purged_auth,
            "expired_conversations": expired_conversations,
        }
