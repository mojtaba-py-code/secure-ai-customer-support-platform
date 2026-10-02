"""Agent desk: the human-handoff queue and staff replies."""

from __future__ import annotations

import uuid
from typing import Annotated

from fastapi import APIRouter, Depends

from aegis.api.deps import Limit, Offset, ServicesDep, require
from aegis.api.v1 import API_V1_PREFIX
from aegis.domain.enums import ConversationStatus, Priority
from aegis.schemas.conversations import (
    AgentReply,
    AssignRequest,
    MessageOut,
    QueueItemOut,
    ResolveRequest,
    StaffConversationDetail,
    StaffMessageOut,
)
from aegis.security.principal import Principal
from aegis.security.rbac import Permission

router = APIRouter(prefix=f"{API_V1_PREFIX}/agent-desk", tags=["agent desk"])

QueueReader = Annotated[Principal, Depends(require(Permission.HANDOFF_QUEUE_READ))]
AnyReader = Annotated[Principal, Depends(require(Permission.CONVERSATION_READ_ANY))]
Claimer = Annotated[Principal, Depends(require(Permission.HANDOFF_CLAIM))]
Assigner = Annotated[Principal, Depends(require(Permission.HANDOFF_ASSIGN_ANY))]
Replier = Annotated[Principal, Depends(require(Permission.HANDOFF_REPLY))]
Resolver = Annotated[Principal, Depends(require(Permission.HANDOFF_RESOLVE))]


@router.get("/queue", response_model=list[QueueItemOut])
async def queue(
    principal: QueueReader,
    services: ServicesDep,
    status: ConversationStatus | None = None,
    priority: Priority | None = None,
    mine: bool = False,
    limit: Limit = 50,
    offset: Offset = 0,
) -> list[QueueItemOut]:
    items = await services.handoff.queue(
        principal, status=status, priority=priority, mine=mine, limit=limit, offset=offset
    )
    return [QueueItemOut.model_validate(c) for c in items]


@router.get("/conversations/{conversation_id}", response_model=StaffConversationDetail)
async def conversation_detail(
    conversation_id: uuid.UUID, principal: AnyReader, services: ServicesDep
) -> StaffConversationDetail:
    conversation = await services.conversations.get(principal, conversation_id)
    messages = await services.conversations.messages(
        principal, conversation.id, before_sequence=None, limit=100
    )
    return StaffConversationDetail(
        id=conversation.id,
        customer_id=conversation.customer_id,
        status=conversation.status,
        subject=conversation.subject,
        escalation_reason=conversation.escalation_reason,
        escalation_priority=conversation.escalation_priority,
        escalated_at=conversation.escalated_at,
        assigned_agent_id=conversation.assigned_agent_id,
        summary=conversation.summary,
        messages=[StaffMessageOut.model_validate(m) for m in messages],
    )


@router.post("/conversations/{conversation_id}/claim", response_model=QueueItemOut)
async def claim(
    conversation_id: uuid.UUID, principal: Claimer, services: ServicesDep
) -> QueueItemOut:
    return QueueItemOut.model_validate(await services.handoff.claim(principal, conversation_id))


@router.post("/conversations/{conversation_id}/assign", response_model=QueueItemOut)
async def assign(
    conversation_id: uuid.UUID, body: AssignRequest, principal: Assigner, services: ServicesDep
) -> QueueItemOut:
    return QueueItemOut.model_validate(
        await services.handoff.assign(principal, conversation_id, body.agent_user_id)
    )


@router.post("/conversations/{conversation_id}/messages", response_model=MessageOut)
async def reply(
    conversation_id: uuid.UUID, body: AgentReply, principal: Replier, services: ServicesDep
) -> MessageOut:
    return MessageOut.model_validate(
        await services.handoff.reply(principal, conversation_id, body.content)
    )


@router.post("/conversations/{conversation_id}/resolve", response_model=QueueItemOut)
async def resolve(
    conversation_id: uuid.UUID, body: ResolveRequest, principal: Resolver, services: ServicesDep
) -> QueueItemOut:
    conversation = await services.handoff.resolve(
        principal, conversation_id, return_to_ai=body.return_to_ai
    )
    return QueueItemOut.model_validate(conversation)
