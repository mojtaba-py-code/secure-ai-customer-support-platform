from __future__ import annotations

from collections.abc import AsyncIterator
from typing import Any

import fakeredis
import pytest

from aegis.kv.base import KeyBuilder, KeyValueStore, KeyValueUnavailable
from aegis.kv.locks import LockNotAcquired, distributed_lock
from aegis.kv.memory import MemoryKeyValueStore
from aegis.kv.rate_limit import RateLimiter, RateLimitPolicy
from aegis.kv.redis_store import RedisKeyValueStore


class Clock:
    def __init__(self, now: float = 1_000_000.0) -> None:
        self.now = now

    def __call__(self) -> float:
        return self.now


@pytest.fixture(params=["memory", "redis"])
async def store(request: pytest.FixtureRequest) -> AsyncIterator[KeyValueStore]:
    if request.param == "memory":
        yield MemoryKeyValueStore()
    else:
        redis_store = RedisKeyValueStore(fakeredis.FakeAsyncRedis(decode_responses=True))
        yield redis_store
        await redis_store.close()


async def test_store_contract(store: KeyValueStore) -> None:
    assert await store.get("k") is None
    await store.set("k", "v", ttl_seconds=60)
    assert await store.get("k") == "v"
    assert await store.set_if_absent("lock", "a", ttl_seconds=60)
    assert not await store.set_if_absent("lock", "b", ttl_seconds=60)
    assert not await store.delete_if_equals("lock", "b")
    assert await store.delete_if_equals("lock", "a")
    assert await store.get("lock") is None
    assert await store.incr("n", ttl_seconds=60) == 1
    assert await store.incr("n", amount=5, ttl_seconds=60) == 6
    await store.delete("n")
    assert await store.get("n") is None
    assert await store.ping()


async def test_memory_store_expiry_and_eviction() -> None:
    clock = Clock(0)
    store = MemoryKeyValueStore(max_entries=3, clock=clock)
    await store.set("a", "1", ttl_seconds=10)
    await store.incr("c", ttl_seconds=10)
    clock.now = 5
    await store.incr("c", ttl_seconds=10)  # keeps the original expiry
    clock.now = 11
    assert await store.get("a") is None
    assert await store.get("c") is None
    for key in ("x", "y", "z", "w"):
        await store.set(key, key, ttl_seconds=100)
    assert await store.get("x") is None  # oldest evicted at capacity
    assert await store.get("w") == "w"


def test_key_builder_hashes_untrusted_parts() -> None:
    keys = KeyBuilder("aegis", "test")
    assert keys.key("rl", "login", "user-1") == "aegis:test:rl:login:user-1"
    hashed = keys.key("rl", "email:evil@example.com\r\nDEL *")
    assert "\n" not in hashed
    assert "evil" not in hashed


async def test_rate_limiter_blocks_after_limit_and_recovers() -> None:
    clock = Clock(1_000_000.0)
    limiter = RateLimiter(MemoryKeyValueStore(), KeyBuilder("aegis", "t"), clock=clock)
    policy = RateLimitPolicy("login", limit=3, window_seconds=60)
    decisions = [await limiter.hit(policy, "ip:1") for _ in range(4)]
    assert [d.allowed for d in decisions] == [True, True, True, False]
    assert decisions[-1].retry_after_seconds >= 1
    assert (await limiter.hit(policy, "ip:2")).allowed  # other identities unaffected
    clock.now += 60 * 2 + 1
    assert (await limiter.hit(policy, "ip:1")).allowed


async def test_sliding_window_counts_previous_window() -> None:
    clock = Clock(1_000_020.0)  # 20 s into a 60 s window
    limiter = RateLimiter(MemoryKeyValueStore(), KeyBuilder("aegis", "t"), clock=clock)
    policy = RateLimitPolicy("api", limit=10, window_seconds=60)
    for _ in range(10):
        assert (await limiter.hit(policy, "u")).allowed
    clock.now += 45  # next window, 5 s in: 92% of the previous window still counts
    assert not (await limiter.hit(policy, "u")).allowed


class BrokenStore(MemoryKeyValueStore):
    async def incr(self, key: str, *, amount: int = 1, ttl_seconds: int) -> int:
        raise KeyValueUnavailable

    async def get(self, key: str) -> Any:
        raise KeyValueUnavailable


async def test_rate_limiter_degrades_to_local_counters_instead_of_failing_open() -> None:
    degraded: list[bool] = []
    limiter = RateLimiter(
        BrokenStore(), KeyBuilder("aegis", "t"), on_degraded=lambda: degraded.append(True)
    )
    policy = RateLimitPolicy("login", limit=2, window_seconds=60)
    results = [(await limiter.hit(policy, "ip")).allowed for _ in range(3)]
    assert results == [True, True, False]
    assert degraded


def test_policy_validation() -> None:
    with pytest.raises(ValueError, match="positive"):
        RateLimitPolicy("x", limit=0, window_seconds=10)


async def test_distributed_lock_is_exclusive_and_released() -> None:
    store = MemoryKeyValueStore()
    async with distributed_lock(store, "lock:conv", ttl_seconds=30):
        with pytest.raises(LockNotAcquired):
            async with distributed_lock(store, "lock:conv", ttl_seconds=30):
                pass
    async with distributed_lock(store, "lock:conv", ttl_seconds=30):
        pass


async def test_lock_release_does_not_delete_a_lock_owned_by_someone_else() -> None:
    store = MemoryKeyValueStore()
    async with distributed_lock(store, "lock:x", ttl_seconds=30):
        await store.set(
            "lock:x", "someone-else", ttl_seconds=30
        )  # our lock expired and was re-acquired
    assert await store.get("lock:x") == "someone-else"
