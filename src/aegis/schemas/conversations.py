"""Conversation, message, turn and pending-action schemas."""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Annotated, Any

from pydantic import Field, StrictBool, StringConstraints

from aegis.domain.enums import (
    ActionStatus,
    ActionType,
    ConversationStatus,
    HandoffReason,
    Priority,
    SenderType,
)
from aegis.schemas.common import RequestModel, ResponseModel


class ConversationCreate(RequestModel):
    subject: Annotated[str, StringConstraints(max_length=200)] | None = None


class ConversationOut(ResponseModel):
    id: uuid.UUID
    status: ConversationStatus
    subject: str | None
    created_at: datetime
    last_message_at: datetime
    message_count: int


class MessageCreate(RequestModel):
    content: Annotated[str, StringConstraints(min_length=1, max_length=4_000)]


class MessageOut(ResponseModel):
    id: uuid.UUID
    sequence: int
    sender_type: SenderType
    content: str
    created_at: datetime


class CitationOut(ResponseModel):
    index: int
    title: str
    section: str


class AssistantMessageOut(MessageOut):
    citations: list[CitationOut] = Field(default_factory=list)


class PendingActionOut(ResponseModel):
    id: uuid.UUID
    action_type: ActionType
    status: ActionStatus
    summary: str
    created_at: datetime
    expires_at: datetime
    result: dict[str, Any] | None = None


class TurnResponse(ResponseModel):
    conversation_id: uuid.UUID
    conversation_status: ConversationStatus
    customer_message: MessageOut
    reply: AssistantMessageOut | None
    intent: str | None
    escalated: bool
    ticket_number: str | None
    pending_actions: list[PendingActionOut]
    notice: str | None = None


class ConversationDetail(ConversationOut):
    messages: list[MessageOut]


class StaffMessageOut(MessageOut):
    meta: dict[str, Any]


class StaffConversationDetail(ResponseModel):
    id: uuid.UUID
    customer_id: uuid.UUID
    status: ConversationStatus
    subject: str | None
    escalation_reason: HandoffReason | None
    escalation_priority: Priority | None
    escalated_at: datetime | None
    assigned_agent_id: uuid.UUID | None
    summary: str | None
    messages: list[StaffMessageOut]


class QueueItemOut(ResponseModel):
    id: uuid.UUID
    status: ConversationStatus
    subject: str | None
    escalation_reason: HandoffReason | None
    escalation_priority: Priority | None
    escalated_at: datetime | None
    assigned_agent_id: uuid.UUID | None
    last_message_at: datetime


class AgentReply(RequestModel):
    content: Annotated[str, StringConstraints(min_length=1, max_length=4_000)]


class AssignRequest(RequestModel):
    agent_user_id: uuid.UUID


class ResolveRequest(RequestModel):
    return_to_ai: StrictBool = False
