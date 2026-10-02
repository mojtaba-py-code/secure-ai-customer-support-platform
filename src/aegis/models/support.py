"""Conversations, messages, support tickets and customer-confirmed pending actions."""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import ForeignKey, Index, Integer, String, UniqueConstraint, text
from sqlalchemy.orm import Mapped, mapped_column

from aegis.core.time import utc_now
from aegis.db.base import (
    Base,
    EncryptedText,
    JSONType,
    TimestampMixin,
    UUIDPrimaryKeyMixin,
    str_enum,
)
from aegis.domain.enums import (
    ActionStatus,
    ActionType,
    ConversationStatus,
    HandoffReason,
    Priority,
    RequestSource,
    SenderType,
    TicketStatus,
)

OPEN_ACTION_SQL = "status IN ('pending', 'executing')"


class Conversation(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    __tablename__ = "conversations"

    customer_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("customers.id", ondelete="RESTRICT"), index=True
    )
    user_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("users.id", ondelete="RESTRICT"))
    status: Mapped[ConversationStatus] = mapped_column(
        str_enum(ConversationStatus, "conversation_status"), default=ConversationStatus.ACTIVE
    )
    subject: Mapped[str | None] = mapped_column(String(200))
    channel: Mapped[str] = mapped_column(String(20), default="web")
    last_message_at: Mapped[datetime] = mapped_column(default=utc_now)
    message_count: Mapped[int] = mapped_column(Integer, default=0)
    assigned_agent_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL")
    )
    escalated_at: Mapped[datetime | None]
    escalation_reason: Mapped[HandoffReason | None] = mapped_column(
        str_enum(HandoffReason, "handoff_reason")
    )
    escalation_priority: Mapped[Priority | None] = mapped_column(
        str_enum(Priority, "escalation_priority")
    )
    summary: Mapped[str | None] = mapped_column(EncryptedText())
    summarized_through: Mapped[int] = mapped_column(Integer, default=0)
    ai_failure_count: Mapped[int] = mapped_column(Integer, default=0)
    suspicious_count: Mapped[int] = mapped_column(Integer, default=0)
    closed_at: Mapped[datetime | None]
    #: Set when the message text was erased (retention period or an erasure request).
    content_erased_at: Mapped[datetime | None]

    __table_args__ = (
        Index("ix_conversations_user_last_message", "user_id", "last_message_at"),
        Index("ix_conversations_queue", "status", "escalation_priority", "escalated_at"),
    )


class Message(UUIDPrimaryKeyMixin, Base):
    __tablename__ = "conversation_messages"

    conversation_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("conversations.id", ondelete="CASCADE")
    )
    sequence: Mapped[int] = mapped_column(Integer)
    sender_type: Mapped[SenderType] = mapped_column(str_enum(SenderType, "sender_type"))
    sender_user_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL")
    )
    content: Mapped[str] = mapped_column(EncryptedText())
    meta: Mapped[dict[str, Any]] = mapped_column(JSONType, default=dict)
    created_at: Mapped[datetime] = mapped_column(default=utc_now)

    __table_args__ = (
        UniqueConstraint("conversation_id", "sequence", name="uq_conversation_messages_sequence"),
    )


class SupportTicket(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    __tablename__ = "support_tickets"

    ticket_number: Mapped[str] = mapped_column(String(16), unique=True)
    customer_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("customers.id", ondelete="RESTRICT"))
    conversation_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("conversations.id", ondelete="SET NULL"), index=True
    )
    created_by_user_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL")
    )
    assigned_to_user_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL")
    )
    subject: Mapped[str] = mapped_column(String(200))
    description: Mapped[str] = mapped_column(EncryptedText())
    category: Mapped[str] = mapped_column(String(40))
    priority: Mapped[Priority] = mapped_column(str_enum(Priority, "ticket_priority"))
    status: Mapped[TicketStatus] = mapped_column(
        str_enum(TicketStatus, "ticket_status"), default=TicketStatus.OPEN
    )
    source: Mapped[RequestSource] = mapped_column(str_enum(RequestSource, "ticket_source"))
    idempotency_key: Mapped[str | None] = mapped_column(String(120), unique=True)
    resolved_at: Mapped[datetime | None]

    __table_args__ = (
        Index("ix_support_tickets_customer_created", "customer_id", "created_at"),
        Index("ix_support_tickets_status_priority", "status", "priority"),
    )


class PendingAction(UUIDPrimaryKeyMixin, Base):
    """A state-changing request proposed by the assistant that only the customer can confirm.

    The model can create one of these (after the eligibility rules passed), but it can never
    confirm it: confirmation is a separate authenticated API call made by the customer's
    client. Eligibility is re-checked at execution time, and the partial unique index allows at
    most one open action per target (e.g. one open refund request per order).
    """

    __tablename__ = "pending_actions"

    conversation_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("conversations.id", ondelete="CASCADE"), index=True
    )
    user_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"))
    customer_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("customers.id", ondelete="RESTRICT"))
    action_type: Mapped[ActionType] = mapped_column(str_enum(ActionType, "action_type"))
    status: Mapped[ActionStatus] = mapped_column(
        str_enum(ActionStatus, "action_status"), default=ActionStatus.PENDING
    )
    params: Mapped[dict[str, Any]] = mapped_column(JSONType)
    summary: Mapped[str] = mapped_column(String(300))
    dedupe_key: Mapped[str] = mapped_column(String(120))
    created_at: Mapped[datetime] = mapped_column(default=utc_now)
    expires_at: Mapped[datetime]
    decided_at: Mapped[datetime | None]
    result: Mapped[dict[str, Any] | None] = mapped_column(JSONType)

    __table_args__ = (
        Index(
            "uq_pending_actions_open_dedupe",
            "dedupe_key",
            unique=True,
            postgresql_where=text(OPEN_ACTION_SQL),
            sqlite_where=text(OPEN_ACTION_SQL),
        ),
    )
