"""Audit events, idempotency records and model usage."""

from __future__ import annotations

import uuid
from datetime import datetime
from decimal import Decimal

from sqlalchemy import delete, func, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from aegis.domain.enums import AuditOutcome
from aegis.models import AuditEvent, IdempotencyRecord, LLMUsage
from aegis.repositories.common import affected_rows, clamp_page


class AuditRepository:
    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    def add(self, event: AuditEvent) -> AuditEvent:
        self._session.add(event)
        return event

    async def list_events(
        self,
        *,
        action_prefix: str | None,
        actor_user_id: uuid.UUID | None,
        outcome: AuditOutcome | None,
        since: datetime | None,
        limit: int,
        offset: int,
    ) -> list[AuditEvent]:
        limit, offset = clamp_page(limit, offset)
        stmt = select(AuditEvent)
        if action_prefix:
            stmt = stmt.where(AuditEvent.action.startswith(action_prefix, autoescape=True))
        if actor_user_id is not None:
            stmt = stmt.where(AuditEvent.actor_user_id == actor_user_id)
        if outcome is not None:
            stmt = stmt.where(AuditEvent.outcome == outcome)
        if since is not None:
            stmt = stmt.where(AuditEvent.occurred_at >= since)
        stmt = (
            stmt.order_by(AuditEvent.occurred_at.desc(), AuditEvent.id).limit(limit).offset(offset)
        )
        return list((await self._session.execute(stmt)).scalars())


class IdempotencyRepository:
    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def get(self, user_id: uuid.UUID, scope: str, key: str) -> IdempotencyRecord | None:
        stmt = select(IdempotencyRecord).where(
            IdempotencyRecord.user_id == user_id,
            IdempotencyRecord.scope == scope,
            IdempotencyRecord.key == key,
        )
        return (await self._session.execute(stmt)).scalar_one_or_none()

    def add(self, record: IdempotencyRecord) -> IdempotencyRecord:
        self._session.add(record)
        return record

    async def complete(self, record_id: uuid.UUID, resource_id: str) -> None:
        await self._session.execute(
            update(IdempotencyRecord)
            .where(IdempotencyRecord.id == record_id)
            .values(status="completed", resource_id=resource_id)
        )

    async def remove(self, record_id: uuid.UUID) -> None:
        await self._session.execute(
            delete(IdempotencyRecord).where(IdempotencyRecord.id == record_id)
        )

    async def purge_expired(self, now: datetime) -> int:
        result = await self._session.execute(
            delete(IdempotencyRecord).where(IdempotencyRecord.expires_at <= now)
        )
        return affected_rows(result)


class UsageRepository:
    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    def add(self, usage: LLMUsage) -> LLMUsage:
        self._session.add(usage)
        return usage

    async def summary_since(self, since: datetime) -> list[tuple[str, str, int, int, int, Decimal]]:
        stmt = (
            select(
                LLMUsage.model,
                LLMUsage.task,
                func.count(),
                func.coalesce(func.sum(LLMUsage.input_tokens), 0),
                func.coalesce(func.sum(LLMUsage.output_tokens), 0),
                func.coalesce(func.sum(LLMUsage.cost_usd), 0),
            )
            .where(LLMUsage.occurred_at >= since)
            .group_by(LLMUsage.model, LLMUsage.task)
            .order_by(LLMUsage.model, LLMUsage.task)
        )
        rows = (await self._session.execute(stmt)).all()
        return [
            (str(r[0]), str(r[1]), int(r[2]), int(r[3]), int(r[4]), Decimal(str(r[5])))
            for r in rows
        ]
