"""HTTP idempotency keys for non-idempotent POST endpoints.

Contract (in the spirit of the IETF ``Idempotency-Key`` draft):

* same key + same request body -> the original result is returned, nothing is executed twice;
* same key + different body -> 422 (a client bug that must not be silently "fixed");
* same key while the first request is still running -> 409, the client retries later;
* a request that fails releases its key so the client can retry it.

The unique constraint on (user, scope, key) makes concurrent duplicates impossible; keys are
scoped per user so one customer can never replay another customer's result.
"""

from __future__ import annotations

import hashlib
import json
import re
import uuid
from dataclasses import dataclass
from datetime import timedelta
from typing import Any

from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from aegis.core.errors import Conflict, ValidationFailed
from aegis.core.time import Clock, utc_now
from aegis.models import IdempotencyRecord
from aegis.repositories.operations import IdempotencyRepository

_KEY_PATTERN = re.compile(r"^[A-Za-z0-9_-]{8,120}$")


@dataclass(frozen=True, slots=True)
class IdempotencyTicket:
    """Either a fresh reservation (``record``) or a completed replay (``replay_resource_id``)."""

    record_id: uuid.UUID | None
    replay_resource_id: str | None


def request_fingerprint(payload: Any) -> str:
    return hashlib.sha256(
        json.dumps(payload, sort_keys=True, default=str).encode("utf-8")
    ).hexdigest()


def validate_idempotency_key(key: str | None) -> str | None:
    if key is None:
        return None
    if not _KEY_PATTERN.fullmatch(key):
        raise ValidationFailed(
            "Idempotency-Key must be 8-120 characters of letters, digits, '-' or '_'."
        )
    return key


class IdempotencyService:
    def __init__(self, session: AsyncSession, *, ttl_seconds: int, clock: Clock = utc_now) -> None:
        self._session = session
        self._repo = IdempotencyRepository(session)
        self._ttl = timedelta(seconds=ttl_seconds)
        self._clock = clock

    async def begin(
        self, *, user_id: uuid.UUID, scope: str, key: str, request_hash: str
    ) -> IdempotencyTicket:
        existing = await self._repo.get(user_id, scope, key)
        now = self._clock()
        if existing is not None and existing.expires_at <= now:
            await self._repo.remove(existing.id)
            await self._session.commit()
            existing = None
        if existing is not None:
            if existing.request_hash != request_hash:
                raise ValidationFailed(
                    "This Idempotency-Key was already used with a different request."
                )
            if existing.status == "completed" and existing.resource_id:
                return IdempotencyTicket(record_id=None, replay_resource_id=existing.resource_id)
            raise Conflict("A request with this Idempotency-Key is still being processed.")
        record = IdempotencyRecord(
            user_id=user_id,
            scope=scope,
            key=key,
            request_hash=request_hash,
            status="in_progress",
            created_at=now,
            expires_at=now + self._ttl,
        )
        self._repo.add(record)
        try:
            await self._session.commit()
        except IntegrityError as exc:
            await self._session.rollback()
            raise Conflict("A request with this Idempotency-Key is still being processed.") from exc
        return IdempotencyTicket(record_id=record.id, replay_resource_id=None)

    async def complete(self, record_id: uuid.UUID, resource_id: str) -> None:
        await self._repo.complete(record_id, resource_id)
        await self._session.commit()

    async def release(self, record_id: uuid.UUID) -> None:
        await self._session.rollback()
        await self._repo.remove(record_id)
        await self._session.commit()
