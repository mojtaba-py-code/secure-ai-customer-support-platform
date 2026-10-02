"""Customer conversations with the assistant, and confirmation of proposed actions."""

from __future__ import annotations

import uuid
from typing import Annotated

from fastapi import APIRouter, Depends, Path, Query, status

from aegis.agents.orchestrator import TurnResult
from aegis.agents.responses import HUMAN_HANDLING
from aegis.api.deps import (
    ContainerDep,
    IdempotencyKeyDep,
    Limit,
    Offset,
    ServicesDep,
    enforce_rate_limit,
    require,
)
from aegis.api.v1 import API_V1_PREFIX
from aegis.bootstrap import RequestServices
from aegis.core.errors import NotFound
from aegis.domain.enums import ActionStatus, SenderType
from aegis.schemas.common import Page
from aegis.schemas.conversations import (
    AssistantMessageOut,
    CitationOut,
    ConversationCreate,
    ConversationDetail,
    ConversationOut,
    MessageCreate,
    MessageOut,
    PendingActionOut,
    TurnResponse,
)
from aegis.security.principal import Principal
from aegis.security.rbac import Permission
from aegis.services.idempotency import request_fingerprint

router = APIRouter(prefix=f"{API_V1_PREFIX}/conversations", tags=["conversations"])

CustomerCreate = Annotated[Principal, Depends(require(Permission.CONVERSATION_CREATE))]
Sender = Annotated[Principal, Depends(require(Permission.MESSAGE_SEND))]
Reader = Annotated[Principal, Depends(require(Permission.CONVERSATION_READ_OWN))]
Confirmer = Annotated[Principal, Depends(require(Permission.ACTION_CONFIRM_OWN))]
ConversationId = Annotated[uuid.UUID, Path()]


@router.post("", status_code=status.HTTP_201_CREATED, response_model=ConversationOut)
async def create_conversation(
    body: ConversationCreate, principal: CustomerCreate, services: ServicesDep
) -> ConversationOut:
    conversation = await services.conversations.create(principal, subject=body.subject)
    return ConversationOut.model_validate(conversation)


@router.get("", response_model=Page[ConversationOut])
async def list_conversations(
    principal: Reader, services: ServicesDep, limit: Limit = 20, offset: Offset = 0
) -> Page[ConversationOut]:
    items = await services.conversations.list_own(principal, limit=limit, offset=offset)
    return Page[ConversationOut](
        items=[ConversationOut.model_validate(c) for c in items], limit=limit, offset=offset
    )


@router.get("/{conversation_id}", response_model=ConversationDetail)
async def get_conversation(
    conversation_id: ConversationId, principal: Reader, services: ServicesDep
) -> ConversationDetail:
    conversation = await services.conversations.get(principal, conversation_id)
    messages = await services.conversations.messages(
        principal, conversation.id, before_sequence=None, limit=50
    )
    return ConversationDetail(
        **ConversationOut.model_validate(conversation).model_dump(),
        messages=[
            MessageOut.model_validate(m) for m in messages if m.sender_type is not SenderType.SYSTEM
        ],
    )


@router.get("/{conversation_id}/messages", response_model=list[MessageOut])
async def list_messages(
    conversation_id: ConversationId,
    principal: Reader,
    services: ServicesDep,
    before: Annotated[int | None, Query(ge=1)] = None,
    limit: Limit = 50,
) -> list[MessageOut]:
    messages = await services.conversations.messages(
        principal, conversation_id, before_sequence=before, limit=limit
    )
    return [
        MessageOut.model_validate(m) for m in messages if m.sender_type is not SenderType.SYSTEM
    ]


async def _pending(
    services: RequestServices, principal: Principal, conversation_id: uuid.UUID, ids: set[str]
) -> list[PendingActionOut]:
    if not ids:
        return []
    actions = await services.actions.list_for_conversation(principal, conversation_id)
    return [
        PendingActionOut.model_validate(a)
        for a in actions
        if str(a.id) in ids and a.status is ActionStatus.PENDING
    ]


async def _turn_response(
    services: RequestServices, principal: Principal, result: TurnResult
) -> TurnResponse:
    reply = None
    if result.reply is not None:
        reply = AssistantMessageOut(
            **MessageOut.model_validate(result.reply).model_dump(),
            citations=[
                CitationOut(index=c.index, title=c.title, section=c.section)
                for c in result.citations
            ],
        )
    return TurnResponse(
        conversation_id=result.conversation_id,
        conversation_status=result.status,
        customer_message=MessageOut.model_validate(result.customer_message),
        reply=reply,
        intent=result.intent,
        escalated=result.escalated,
        ticket_number=result.ticket_number,
        pending_actions=await _pending(
            services, principal, result.conversation_id, {a.action_id for a in result.actions}
        ),
        notice=HUMAN_HANDLING if result.reply is None else None,
    )


async def _replay(
    services: RequestServices, principal: Principal, conversation_id: uuid.UUID, message_id: str
) -> TurnResponse:
    conversation = await services.conversations.get(principal, conversation_id)
    messages = await services.conversations.messages(
        principal, conversation.id, before_sequence=None, limit=100
    )
    by_id = {str(m.id): m for m in messages}
    customer = by_id.get(message_id)
    if customer is None:
        raise NotFound
    reply = next(
        (
            m
            for m in messages
            if m.sequence == customer.sequence + 1 and m.sender_type is SenderType.ASSISTANT
        ),
        None,
    )
    citations = (reply.meta or {}).get("citations", []) if reply else []
    return TurnResponse(
        conversation_id=conversation.id,
        conversation_status=conversation.status,
        customer_message=MessageOut.model_validate(customer),
        reply=AssistantMessageOut(
            **MessageOut.model_validate(reply).model_dump(),
            citations=[
                CitationOut(index=c["index"], title=c["title"], section=c["section"])
                for c in citations
            ],
        )
        if reply
        else None,
        intent=(reply.meta or {}).get("intent") if reply else None,
        escalated=bool((reply.meta or {}).get("escalated")) if reply else False,
        ticket_number=(reply.meta or {}).get("ticket") if reply else None,
        pending_actions=[],
        notice=None if reply else HUMAN_HANDLING,
    )


@router.post("/{conversation_id}/messages", response_model=TurnResponse)
async def send_message(
    conversation_id: ConversationId,
    body: MessageCreate,
    principal: Sender,
    container: ContainerDep,
    services: ServicesDep,
    idempotency_key: IdempotencyKeyDep,
) -> TurnResponse:
    """Send a message to the assistant and receive its validated reply.

    Supports ``Idempotency-Key``: a retried request returns the original reply instead of
    running the assistant (and its tools) a second time.
    """
    await enforce_rate_limit(
        container, container.rate_limits.llm_minute, f"user:{principal.user_id}"
    )
    await enforce_rate_limit(container, container.rate_limits.llm_day, f"user:{principal.user_id}")
    record_id = None
    if idempotency_key is not None:
        ticket = await services.idempotency.begin(
            user_id=principal.user_id,
            scope=f"message:{conversation_id}",
            key=idempotency_key,
            request_hash=request_fingerprint(body.model_dump()),
        )
        if ticket.replay_resource_id is not None:
            return await _replay(services, principal, conversation_id, ticket.replay_resource_id)
        record_id = ticket.record_id
    try:
        result = await container.agent.handle_message(
            principal, conversation_id, body.content, services
        )
    except Exception:
        if record_id is not None:
            await services.idempotency.release(record_id)
        raise
    if record_id is not None:
        await services.idempotency.complete(record_id, str(result.customer_message.id))
    return await _turn_response(services, principal, result)


@router.post("/{conversation_id}/close", response_model=ConversationOut)
async def close_conversation(
    conversation_id: ConversationId, principal: Reader, services: ServicesDep
) -> ConversationOut:
    return ConversationOut.model_validate(
        await services.conversations.close(principal, conversation_id)
    )


@router.get("/{conversation_id}/actions", response_model=list[PendingActionOut])
async def list_actions(
    conversation_id: ConversationId, principal: Reader, services: ServicesDep
) -> list[PendingActionOut]:
    actions = await services.actions.list_for_conversation(principal, conversation_id)
    return [PendingActionOut.model_validate(a) for a in actions]


@router.post("/{conversation_id}/actions/{action_id}/confirm", response_model=PendingActionOut)
async def confirm_action(
    conversation_id: ConversationId,
    action_id: uuid.UUID,
    principal: Confirmer,
    services: ServicesDep,
) -> PendingActionOut:
    """Execute a refund request or cancellation that the assistant prepared (customer only)."""
    return PendingActionOut.model_validate(
        await services.actions.confirm(principal, conversation_id, action_id)
    )


@router.post("/{conversation_id}/actions/{action_id}/decline", response_model=PendingActionOut)
async def decline_action(
    conversation_id: ConversationId,
    action_id: uuid.UUID,
    principal: Confirmer,
    services: ServicesDep,
) -> PendingActionOut:
    return PendingActionOut.model_validate(
        await services.actions.decline(principal, conversation_id, action_id)
    )
