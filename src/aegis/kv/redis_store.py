"""Redis-backed key-value store (production).

Atomicity without server-side scripts: counters use a MULTI/EXEC pipeline (``INCRBY`` +
``EXPIRE NX``), compare-and-delete uses optimistic locking (``WATCH``). Connection and timeout
problems surface as :class:`KeyValueUnavailable` so callers can degrade deliberately.

Server-side hardening (see ``docker/redis/redis.conf``): ACL user restricted to the ``aegis:*``
key pattern with dangerous commands disabled, ``maxmemory`` with ``volatile-lru`` eviction
(every key we write has a TTL), protected mode, and no persistence of this ephemeral data.
"""

from __future__ import annotations

from typing import Any

import redis.asyncio as aioredis
from redis.exceptions import RedisError, WatchError

from aegis.kv.base import KeyValueUnavailable


class RedisKeyValueStore:
    def __init__(self, client: aioredis.Redis) -> None:
        self._redis = client

    @classmethod
    def from_url(cls, url: str, *, socket_timeout: float) -> RedisKeyValueStore:
        client = aioredis.Redis.from_url(
            url,
            decode_responses=True,
            socket_timeout=socket_timeout,
            socket_connect_timeout=socket_timeout,
            health_check_interval=30,
        )
        return cls(client)

    async def _run(self, coro: Any) -> Any:
        try:
            return await coro
        except RedisError as exc:
            raise KeyValueUnavailable(log_message=f"redis error: {type(exc).__name__}") from exc

    async def get(self, key: str) -> str | None:
        value = await self._run(self._redis.get(key))
        return None if value is None else str(value)

    async def set(self, key: str, value: str, *, ttl_seconds: int) -> None:
        await self._run(self._redis.set(key, value, ex=max(1, ttl_seconds)))

    async def set_if_absent(self, key: str, value: str, *, ttl_seconds: int) -> bool:
        return bool(await self._run(self._redis.set(key, value, ex=max(1, ttl_seconds), nx=True)))

    async def delete(self, key: str) -> None:
        await self._run(self._redis.delete(key))

    async def delete_if_equals(self, key: str, expected: str) -> bool:
        try:
            async with self._redis.pipeline(transaction=True) as pipe:
                await pipe.watch(key)
                current = await pipe.get(key)
                if current != expected:
                    await pipe.unwatch()  # type: ignore[no-untyped-call]
                    return False
                pipe.multi()  # type: ignore[no-untyped-call]
                pipe.delete(key)
                result = await pipe.execute()
                return bool(result and result[0])
        except WatchError:
            return False
        except RedisError as exc:
            raise KeyValueUnavailable(log_message=f"redis error: {type(exc).__name__}") from exc

    async def incr(self, key: str, *, amount: int = 1, ttl_seconds: int) -> int:
        try:
            async with self._redis.pipeline(transaction=True) as pipe:
                pipe.incrby(key, amount)
                pipe.expire(key, max(1, ttl_seconds), nx=True)
                result = await pipe.execute()
        except RedisError as exc:
            raise KeyValueUnavailable(log_message=f"redis error: {type(exc).__name__}") from exc
        return int(result[0])

    async def ping(self) -> bool:
        try:
            return bool(await self._redis.ping())
        except RedisError:
            return False

    async def close(self) -> None:
        await self._redis.aclose()
