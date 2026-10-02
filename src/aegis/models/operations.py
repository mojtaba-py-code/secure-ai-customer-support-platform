"""Operational records: the audit trail, idempotency keys and model usage accounting."""

from __future__ import annotations

import uuid
from datetime import datetime
from decimal import Decimal
from typing import Any

from sqlalchemy import ForeignKey, Index, Integer, Numeric, String, UniqueConstraint, Uuid
from sqlalchemy.orm import Mapped, mapped_column

from aegis.core.time import utc_now
from aegis.db.base import Base, JSONType, UUIDPrimaryKeyMixin, str_enum
from aegis.domain.enums import AuditOutcome


class AuditEvent(UUIDPrimaryKeyMixin, Base):
    """Append-only security audit trail.

    The actor is recorded by id without a foreign key, so deleting or anonymising a user can
    never rewrite history. On PostgreSQL a trigger rejects UPDATE and DELETE and the runtime
    database role has only INSERT/SELECT on this table (see the migrations).
    """

    __tablename__ = "audit_events"

    occurred_at: Mapped[datetime] = mapped_column(default=utc_now)
    actor_user_id: Mapped[uuid.UUID | None] = mapped_column(Uuid())
    actor_role: Mapped[str | None] = mapped_column(String(32))
    action: Mapped[str] = mapped_column(String(80))
    resource_type: Mapped[str | None] = mapped_column(String(40))
    resource_id: Mapped[str | None] = mapped_column(String(64))
    outcome: Mapped[AuditOutcome] = mapped_column(str_enum(AuditOutcome, "audit_outcome"))
    request_id: Mapped[str | None] = mapped_column(String(64))
    ip_address: Mapped[str | None] = mapped_column(String(45))
    details: Mapped[dict[str, Any]] = mapped_column(JSONType, default=dict)

    __table_args__ = (
        Index("ix_audit_events_occurred_at", "occurred_at"),
        Index("ix_audit_events_actor", "actor_user_id", "occurred_at"),
        Index("ix_audit_events_action", "action", "occurred_at"),
    )


class IdempotencyRecord(UUIDPrimaryKeyMixin, Base):
    """``Idempotency-Key`` bookkeeping for non-idempotent POST endpoints.

    The unique constraint on (user, scope, key) is what makes a retried request safe even when
    two retries race: only one insert can win. The response is re-rendered from the stored
    resource id instead of caching a response body that could contain customer data.
    """

    __tablename__ = "idempotency_records"

    user_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"))
    scope: Mapped[str] = mapped_column(String(60))
    key: Mapped[str] = mapped_column(String(120))
    request_hash: Mapped[str] = mapped_column(String(64))
    status: Mapped[str] = mapped_column(String(20), default="in_progress")
    resource_id: Mapped[str | None] = mapped_column(String(64))
    created_at: Mapped[datetime] = mapped_column(default=utc_now)
    expires_at: Mapped[datetime]

    __table_args__ = (
        UniqueConstraint("user_id", "scope", "key", name="uq_idempotency_records_user_scope_key"),
        Index("ix_idempotency_records_expires_at", "expires_at"),
    )


class LLMUsage(UUIDPrimaryKeyMixin, Base):
    __tablename__ = "llm_usage"

    occurred_at: Mapped[datetime] = mapped_column(default=utc_now)
    user_id: Mapped[uuid.UUID | None] = mapped_column(Uuid())
    conversation_id: Mapped[uuid.UUID | None] = mapped_column(Uuid())
    task: Mapped[str] = mapped_column(String(20))
    provider: Mapped[str] = mapped_column(String(20))
    model: Mapped[str] = mapped_column(String(60))
    input_tokens: Mapped[int] = mapped_column(Integer, default=0)
    output_tokens: Mapped[int] = mapped_column(Integer, default=0)
    cache_read_tokens: Mapped[int] = mapped_column(Integer, default=0)
    cache_write_tokens: Mapped[int] = mapped_column(Integer, default=0)
    cost_usd: Mapped[Decimal] = mapped_column(Numeric(12, 6), default=Decimal(0))
    latency_ms: Mapped[int] = mapped_column(Integer, default=0)
    outcome: Mapped[str] = mapped_column(String(20))

    __table_args__ = (
        Index("ix_llm_usage_occurred_at", "occurred_at"),
        Index("ix_llm_usage_user", "user_id", "occurred_at"),
    )
