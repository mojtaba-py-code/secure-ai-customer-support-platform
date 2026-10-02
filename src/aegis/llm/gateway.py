"""The single entry point for model calls: routing, limits, resilience and accounting.

Responsibilities:

* **Model selection by task** - the agent turn uses the capable model, classification and
  summaries a small, cheap one.
* **Cost control** - a per-user daily token budget and a global daily spend cap (in the shared
  key-value store) are checked before every call and charged after it.
* **Resilience** - a hard timeout per call and a circuit breaker around the provider.
* **Graceful degradation** - when the provider is down, the breaker is open or a budget is
  exhausted, the call is served by the deterministic offline model instead (grounded, template
  based, free), and the response is flagged ``degraded`` so callers and metrics can tell.
* **Accounting** - every call is recorded (tokens, estimated cost, latency, outcome).
"""

from __future__ import annotations

import asyncio
import dataclasses
import logging
import uuid
from dataclasses import dataclass
from typing import Protocol

from aegis.core.errors import BudgetExceeded
from aegis.core.resilience import CircuitBreaker
from aegis.core.time import day_key
from aegis.kv.base import KeyBuilder, KeyValueStore, KeyValueUnavailable
from aegis.llm.base import LLMProvider, LLMRequestRejected, LLMUnavailable
from aegis.llm.pricing import estimate_cost
from aegis.llm.types import LLMRequest, LLMResponse, LLMTask, TokenUsage
from aegis.observability import metrics

logger = logging.getLogger(__name__)


@dataclass(frozen=True, slots=True)
class ModelRoutes:
    agent: str
    classify: str
    summarize: str

    def for_task(self, task: LLMTask) -> str:
        return {
            LLMTask.AGENT: self.agent,
            LLMTask.CLASSIFY: self.classify,
            LLMTask.SUMMARIZE: self.summarize,
        }[task]


@dataclass(frozen=True, slots=True)
class UsageEvent:
    task: str
    provider: str
    model: str
    usage: TokenUsage
    cost_usd: float
    latency_ms: int
    outcome: str
    user_id: uuid.UUID | None
    conversation_id: uuid.UUID | None


class UsageSink(Protocol):
    async def record(self, event: UsageEvent) -> None: ...


class BudgetGuard:
    """Daily token budget per user and daily spend cap for the whole deployment."""

    _MICRO = 1_000_000

    def __init__(
        self,
        store: KeyValueStore,
        keys: KeyBuilder,
        *,
        user_daily_tokens: int,
        global_daily_cost_usd: float,
    ) -> None:
        self._store = store
        self._keys = keys
        self._user_limit = user_daily_tokens
        self._global_limit_micro = int(global_daily_cost_usd * self._MICRO)

    async def exhausted(self, user_id: uuid.UUID | None) -> str | None:
        """Name of the exhausted budget, or ``None``. An unreachable store counts as exhausted."""
        day = day_key()
        try:
            spent_global = await self._store.get(self._keys.key("budget", "global", day))
            if spent_global is not None and int(spent_global) >= self._global_limit_micro:
                return "global_budget"
            if user_id is not None:
                spent_user = await self._store.get(
                    self._keys.key("budget", "user", str(user_id), day)
                )
                if spent_user is not None and int(spent_user) >= self._user_limit:
                    return "user_budget"
        except KeyValueUnavailable:
            return "budget_unverifiable"
        return None

    async def charge(self, user_id: uuid.UUID | None, *, tokens: int, cost_usd: float) -> None:
        day = day_key()
        try:
            await self._store.incr(
                self._keys.key("budget", "global", day),
                amount=int(cost_usd * self._MICRO),
                ttl_seconds=172_800,
            )
            if user_id is not None:
                await self._store.incr(
                    self._keys.key("budget", "user", str(user_id), day),
                    amount=tokens,
                    ttl_seconds=172_800,
                )
        except KeyValueUnavailable:
            logger.warning(
                "could not record model spend", extra={"event": "llm.budget_record_failed"}
            )


class LLMGateway:
    def __init__(
        self,
        *,
        primary: LLMProvider,
        fallback: LLMProvider | None,
        routes: ModelRoutes,
        budget: BudgetGuard,
        breaker: CircuitBreaker,
        call_timeout_seconds: float,
        usage_sink: UsageSink | None = None,
    ) -> None:
        self._primary = primary
        self._fallback = fallback
        self._routes = routes
        self._budget = budget
        self._breaker = breaker
        self._timeout = call_timeout_seconds
        self._usage_sink = usage_sink

    async def complete(
        self,
        request: LLMRequest,
        *,
        user_id: uuid.UUID | None = None,
        conversation_id: uuid.UUID | None = None,
    ) -> LLMResponse:
        if self._fallback is None or self._primary is self._fallback:
            return await self._call(
                self._primary, request, user_id, conversation_id, degraded_reason=None
            )

        reason = await self._budget.exhausted(user_id)
        if reason is None and not self._breaker.allow():
            reason = "circuit_open"
        if reason is None:
            try:
                response = await self._call(
                    self._primary, request, user_id, conversation_id, degraded_reason=None
                )
            except (LLMUnavailable, TimeoutError):
                self._breaker.record_failure()
                self._publish_breaker_state()
                reason = "provider_unavailable"
            except LLMRequestRejected:
                self._breaker.release_trial()
                reason = "request_rejected"
            except BaseException:
                self._breaker.release_trial()
                raise
            else:
                self._breaker.record_success()
                self._publish_breaker_state()
                return response

        logger.warning(
            "serving model call from the offline fallback",
            extra={"event": "llm.degraded", "reason": reason},
        )
        return await self._call(
            self._fallback, request, user_id, conversation_id, degraded_reason=reason
        )

    async def _call(
        self,
        provider: LLMProvider,
        request: LLMRequest,
        user_id: uuid.UUID | None,
        conversation_id: uuid.UUID | None,
        *,
        degraded_reason: str | None,
    ) -> LLMResponse:
        if degraded_reason is None and provider is self._primary and self._fallback is None:
            exhausted = await self._budget.exhausted(user_id)
            if exhausted is not None:
                raise BudgetExceeded(log_message=f"model budget exhausted: {exhausted}")
        model = "offline" if degraded_reason is not None else self._routes.for_task(request.task)
        try:
            async with asyncio.timeout(self._timeout):
                response = await provider.complete(request, model=model)
        except TimeoutError:
            metrics.LLM_REQUESTS.labels(
                provider=provider.name, task=request.task.value, outcome="timeout"
            ).inc()
            raise
        except Exception:
            metrics.LLM_REQUESTS.labels(
                provider=provider.name, task=request.task.value, outcome="error"
            ).inc()
            raise
        outcome = response.stop_reason.value
        metrics.LLM_REQUESTS.labels(
            provider=provider.name, task=request.task.value, outcome=outcome
        ).inc()
        cost = estimate_cost(response.model, response.usage)
        metrics.LLM_LATENCY.labels(provider=provider.name, task=request.task.value).observe(
            response.latency_ms / 1000
        )
        for kind, value in (
            ("input", response.usage.input_tokens),
            ("output", response.usage.output_tokens),
            ("cache_read", response.usage.cache_read_tokens),
            ("cache_write", response.usage.cache_write_tokens),
        ):
            if value:
                metrics.LLM_TOKENS.labels(
                    provider=provider.name, model=response.model, kind=kind
                ).inc(value)
        if cost:
            metrics.LLM_COST.labels(model=response.model).inc(cost)
            await self._budget.charge(user_id, tokens=response.usage.total, cost_usd=cost)
        await self._record_usage(
            UsageEvent(
                task=request.task.value,
                provider=provider.name,
                model=response.model,
                usage=response.usage,
                cost_usd=cost,
                latency_ms=response.latency_ms,
                outcome=outcome,
                user_id=user_id,
                conversation_id=conversation_id,
            )
        )
        return dataclasses.replace(
            response,
            cost_usd=cost,
            degraded=degraded_reason is not None,
            degraded_reason=degraded_reason,
        )

    async def _record_usage(self, event: UsageEvent) -> None:
        if self._usage_sink is None:
            return
        try:
            await self._usage_sink.record(event)
        except Exception:  # accounting must never break a customer reply
            logger.exception(
                "failed to record model usage", extra={"event": "llm.usage_record_failed"}
            )

    def _publish_breaker_state(self) -> None:
        state = self._breaker.state.value
        metrics.CIRCUIT_STATE.labels(circuit=self._breaker.name).set(0 if state == "closed" else 1)

    async def close(self) -> None:
        await self._primary.close()
        if self._fallback is not None and self._fallback is not self._primary:
            await self._fallback.close()
