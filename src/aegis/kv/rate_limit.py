"""Sliding-window rate limiting.

Algorithm: *sliding window counter* - two fixed windows, the previous one weighted by how much
of it still overlaps the sliding window. It smooths the burst-at-the-boundary weakness of plain
fixed windows with two O(1) operations per request. Rejected requests still count, so a client
that keeps hammering stays blocked instead of being let through at the start of each window.

Failure mode: if Redis is unreachable the limiter does NOT fail open. It degrades to an
in-process counter with the same policy (per replica, so slightly more permissive), logs it and
counts it in metrics. Authentication and LLM endpoints therefore stay protected during a cache
outage.
"""

from __future__ import annotations

import logging
import math
import time
from collections.abc import Callable
from dataclasses import dataclass

from aegis.kv.base import KeyBuilder, KeyValueStore, KeyValueUnavailable
from aegis.kv.memory import MemoryKeyValueStore

logger = logging.getLogger(__name__)


@dataclass(frozen=True, slots=True)
class RateLimitPolicy:
    name: str
    limit: int
    window_seconds: int

    def __post_init__(self) -> None:
        if self.limit < 1 or self.window_seconds < 1:
            msg = "limit and window_seconds must be positive"
            raise ValueError(msg)


@dataclass(frozen=True, slots=True)
class RateLimitDecision:
    allowed: bool
    limit: int
    remaining: int
    retry_after_seconds: int


class RateLimiter:
    def __init__(
        self,
        store: KeyValueStore,
        keys: KeyBuilder,
        *,
        fallback: MemoryKeyValueStore | None = None,
        clock: Callable[[], float] = time.time,
        on_degraded: Callable[[], None] | None = None,
    ) -> None:
        self._store = store
        self._keys = keys
        self._fallback = fallback or MemoryKeyValueStore()
        self._clock = clock
        self._on_degraded = on_degraded

    async def hit(self, policy: RateLimitPolicy, identity: str) -> RateLimitDecision:
        now = self._clock()
        window = policy.window_seconds
        index = int(now // window)
        elapsed_fraction = (now % window) / window
        current_key = self._keys.key("rl", policy.name, identity, index)
        previous_key = self._keys.key("rl", policy.name, identity, index - 1)
        try:
            count, previous = await self._count(self._store, current_key, previous_key, window)
        except KeyValueUnavailable:
            logger.warning(
                "rate limiter degraded to in-process counters",
                extra={"event": "rate_limit.degraded", "policy": policy.name},
            )
            if self._on_degraded is not None:
                self._on_degraded()
            count, previous = await self._count(self._fallback, current_key, previous_key, window)

        estimated = previous * (1.0 - elapsed_fraction) + count
        if estimated > policy.limit:
            retry_after = max(1, math.ceil(window * (1.0 - elapsed_fraction)))
            return RateLimitDecision(False, policy.limit, 0, retry_after)
        return RateLimitDecision(
            True, policy.limit, max(0, math.floor(policy.limit - estimated)), 0
        )

    @staticmethod
    async def _count(
        store: KeyValueStore, current_key: str, previous_key: str, window: int
    ) -> tuple[int, int]:
        count = await store.incr(current_key, ttl_seconds=window * 2)
        previous_raw = await store.get(previous_key)
        previous = int(previous_raw) if previous_raw and previous_raw.isdigit() else 0
        return count, previous
