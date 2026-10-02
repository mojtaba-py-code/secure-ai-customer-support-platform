"""Model usage accounting (implements the gateway's ``UsageSink``)."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import timedelta
from decimal import Decimal

from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from aegis.core.time import utc_now
from aegis.llm.gateway import UsageEvent
from aegis.models import LLMUsage
from aegis.repositories.operations import UsageRepository


@dataclass(frozen=True, slots=True)
class UsageLine:
    model: str
    task: str
    calls: int
    input_tokens: int
    output_tokens: int
    cost_usd: Decimal


class UsageService:
    def __init__(self, sessionmaker: async_sessionmaker[AsyncSession]) -> None:
        self._sessionmaker = sessionmaker

    async def record(self, event: UsageEvent) -> None:
        async with self._sessionmaker() as session:
            UsageRepository(session).add(
                LLMUsage(
                    occurred_at=utc_now(),
                    user_id=event.user_id,
                    conversation_id=event.conversation_id,
                    task=event.task,
                    provider=event.provider,
                    model=event.model[:60],
                    input_tokens=event.usage.input_tokens,
                    output_tokens=event.usage.output_tokens,
                    cache_read_tokens=event.usage.cache_read_tokens,
                    cache_write_tokens=event.usage.cache_write_tokens,
                    cost_usd=Decimal(str(event.cost_usd)),
                    latency_ms=event.latency_ms,
                    outcome=event.outcome[:20],
                )
            )
            await session.commit()

    async def summary(self, *, days: int) -> list[UsageLine]:
        since = utc_now() - timedelta(days=max(1, min(days, 90)))
        async with self._sessionmaker() as session:
            rows = await UsageRepository(session).summary_since(since)
        return [UsageLine(*row) for row in rows]
