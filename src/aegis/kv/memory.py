"""In-process key-value store.

Used by tests, by the no-Docker development setup and as the *degraded-mode* fallback of the
rate limiter when Redis is unreachable. It is per-process, so it is refused as the primary
store in production (limits and locks must be shared across replicas).
"""

from __future__ import annotations

import asyncio
import time
from collections.abc import Callable


class MemoryKeyValueStore:
    def __init__(
        self, *, max_entries: int = 100_000, clock: Callable[[], float] = time.monotonic
    ) -> None:
        self._data: dict[str, tuple[str, float]] = {}
        self._lock = asyncio.Lock()
        self._max_entries = max_entries
        self._clock = clock

    def _live(self, key: str) -> str | None:
        item = self._data.get(key)
        if item is None:
            return None
        value, expires_at = item
        if expires_at <= self._clock():
            del self._data[key]
            return None
        return value

    def _store(self, key: str, value: str, ttl_seconds: int, *, keep_expiry: bool = False) -> None:
        if keep_expiry and key in self._data:
            expires_at = self._data[key][1]
        else:
            expires_at = self._clock() + max(1, ttl_seconds)
        if key not in self._data and len(self._data) >= self._max_entries:
            self._evict()
        self._data[key] = (value, expires_at)

    def _evict(self) -> None:
        now = self._clock()
        for key in [k for k, (_, exp) in self._data.items() if exp <= now]:
            del self._data[key]
        while len(self._data) >= self._max_entries:
            del self._data[next(iter(self._data))]

    async def get(self, key: str) -> str | None:
        async with self._lock:
            return self._live(key)

    async def set(self, key: str, value: str, *, ttl_seconds: int) -> None:
        async with self._lock:
            self._store(key, value, ttl_seconds)

    async def set_if_absent(self, key: str, value: str, *, ttl_seconds: int) -> bool:
        async with self._lock:
            if self._live(key) is not None:
                return False
            self._store(key, value, ttl_seconds)
            return True

    async def delete(self, key: str) -> None:
        async with self._lock:
            self._data.pop(key, None)

    async def delete_if_equals(self, key: str, expected: str) -> bool:
        async with self._lock:
            if self._live(key) != expected:
                return False
            del self._data[key]
            return True

    async def incr(self, key: str, *, amount: int = 1, ttl_seconds: int) -> int:
        async with self._lock:
            current = self._live(key)
            value = (int(current) if current is not None else 0) + amount
            self._store(key, str(value), ttl_seconds, keep_expiry=current is not None)
            return value

    async def ping(self) -> bool:
        return True

    async def close(self) -> None:
        async with self._lock:
            self._data.clear()
