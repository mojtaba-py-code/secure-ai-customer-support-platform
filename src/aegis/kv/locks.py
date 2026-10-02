"""Distributed mutual exclusion with owner tokens and a TTL.

Used to serialise work on one conversation (two browser tabs sending at once must not run two
agent turns - and two sets of tool calls - concurrently). The TTL bounds how long a crashed
worker can hold the lock; release only deletes the key if we still own it.
"""

from __future__ import annotations

import logging
import secrets
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from aegis.core.errors import Conflict
from aegis.kv.base import KeyValueStore, KeyValueUnavailable

logger = logging.getLogger(__name__)


class LockNotAcquired(Conflict):
    code = "resource_busy"
    default_message = "This conversation is already processing a message. Please wait a moment."


@asynccontextmanager
async def distributed_lock(
    store: KeyValueStore, key: str, *, ttl_seconds: int
) -> AsyncIterator[None]:
    token = secrets.token_hex(16)
    if not await store.set_if_absent(key, token, ttl_seconds=ttl_seconds):
        raise LockNotAcquired
    try:
        yield
    finally:
        try:
            await store.delete_if_equals(key, token)
        except KeyValueUnavailable:
            logger.warning(
                "lock release failed; it will expire", extra={"event": "lock.release_failed"}
            )
