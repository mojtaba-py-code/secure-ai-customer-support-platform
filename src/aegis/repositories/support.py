"""Conversations, messages, tickets and pending actions."""

from __future__ import annotations

import uuid
from collections.abc import Sequence
from datetime import datetime
from typing import Any

from sqlalchemy import func, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from aegis.domain.enums import (
    ActionStatus,
    ConversationStatus,
    Priority,
    SenderType,
    TicketStatus,
)
from aegis.models import Conversation, Message, PendingAction, SupportTicket
from aegis.repositories.common import affected_rows, clamp_page


class ConversationRepository:
    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    def add(self, conversation: Conversation) -> Conversation:
        self._session.add(conversation)
        return conversation

    async def get(self, conversation_id: uuid.UUID) -> Conversation | None:
        return await self._session.get(Conversation, conversation_id)

    async def get_for_user(
        self, conversation_id: uuid.UUID, user_id: uuid.UUID
    ) -> Conversation | None:
        stmt = select(Conversation).where(
            Conversation.id == conversation_id, Conversation.user_id == user_id
        )
        return (await self._session.execute(stmt)).scalar_one_or_none()

    async def get_for_update(self, conversation_id: uuid.UUID) -> Conversation | None:
        stmt = (
            select(Conversation)
            .where(Conversation.id == conversation_id)
            .with_for_update()
            .execution_options(populate_existing=True)
        )
        return (await self._session.execute(stmt)).scalar_one_or_none()

    async def list_for_user(
        self, user_id: uuid.UUID, *, limit: int, offset: int
    ) -> list[Conversation]:
        limit, offset = clamp_page(limit, offset)
        stmt = (
            select(Conversation)
            .where(Conversation.user_id == user_id)
            .order_by(Conversation.last_message_at.desc(), Conversation.id)
            .limit(limit)
            .offset(offset)
        )
        return list((await self._session.execute(stmt)).scalars())

    async def queue(
        self,
        *,
        statuses: Sequence[ConversationStatus],
        priority: Priority | None,
        assigned_to: uuid.UUID | None,
        limit: int,
        offset: int,
    ) -> list[Conversation]:
        limit, offset = clamp_page(limit, offset)
        stmt = select(Conversation).where(Conversation.status.in_(list(statuses)))
        if priority is not None:
            stmt = stmt.where(Conversation.escalation_priority == priority)
        if assigned_to is not None:
            stmt = stmt.where(Conversation.assigned_agent_id == assigned_to)
        stmt = (
            stmt.order_by(Conversation.escalated_at.asc(), Conversation.id)
            .limit(limit)
            .offset(offset)
        )
        return list((await self._session.execute(stmt)).scalars())

    async def append_message(
        self,
        conversation: Conversation,
        *,
        sender_type: SenderType,
        content: str,
        now: datetime,
        sender_user_id: uuid.UUID | None = None,
        meta: dict[str, Any] | None = None,
    ) -> Message:
        """Append with a gap-free per-conversation sequence number.

        The conversation row must have been loaded with :meth:`get_for_update` (row lock on
        PostgreSQL) so concurrent appends serialise; the unique (conversation, sequence)
        constraint is the backstop.
        """
        conversation.message_count += 1
        conversation.last_message_at = now
        message = Message(
            conversation_id=conversation.id,
            sequence=conversation.message_count,
            sender_type=sender_type,
            sender_user_id=sender_user_id,
            content=content,
            meta=meta or {},
            created_at=now,
        )
        self._session.add(message)
        return message

    async def recent_messages(self, conversation_id: uuid.UUID, *, limit: int) -> list[Message]:
        stmt = (
            select(Message)
            .where(Message.conversation_id == conversation_id)
            .order_by(Message.sequence.desc())
            .limit(max(0, min(limit, 200)))
        )
        return list(reversed(list((await self._session.execute(stmt)).scalars())))

    async def messages_page(
        self, conversation_id: uuid.UUID, *, before_sequence: int | None, limit: int
    ) -> list[Message]:
        limit, _ = clamp_page(limit, 0)
        stmt = select(Message).where(Message.conversation_id == conversation_id)
        if before_sequence is not None:
            stmt = stmt.where(Message.sequence < before_sequence)
        stmt = stmt.order_by(Message.sequence.desc()).limit(limit)
        return list(reversed(list((await self._session.execute(stmt)).scalars())))

    async def messages_in_range(
        self, conversation_id: uuid.UUID, *, after: int, through: int
    ) -> list[Message]:
        stmt = (
            select(Message)
            .where(
                Message.conversation_id == conversation_id,
                Message.sequence > after,
                Message.sequence <= through,
            )
            .order_by(Message.sequence)
        )
        return list((await self._session.execute(stmt)).scalars())


class TicketRepository:
    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    def add(self, ticket: SupportTicket) -> SupportTicket:
        self._session.add(ticket)
        return ticket

    async def get(self, ticket_id: uuid.UUID) -> SupportTicket | None:
        return await self._session.get(SupportTicket, ticket_id)

    async def get_for_customer(
        self, customer_id: uuid.UUID, ticket_id: uuid.UUID
    ) -> SupportTicket | None:
        stmt = select(SupportTicket).where(
            SupportTicket.id == ticket_id, SupportTicket.customer_id == customer_id
        )
        return (await self._session.execute(stmt)).scalar_one_or_none()

    async def get_by_number_for_customer(
        self, customer_id: uuid.UUID, ticket_number: str
    ) -> SupportTicket | None:
        stmt = select(SupportTicket).where(
            SupportTicket.ticket_number == ticket_number.strip().upper(),
            SupportTicket.customer_id == customer_id,
        )
        return (await self._session.execute(stmt)).scalar_one_or_none()

    async def get_by_idempotency_key(self, key: str) -> SupportTicket | None:
        stmt = select(SupportTicket).where(SupportTicket.idempotency_key == key)
        return (await self._session.execute(stmt)).scalar_one_or_none()

    async def open_ticket_for_conversation(
        self, conversation_id: uuid.UUID
    ) -> SupportTicket | None:
        stmt = (
            select(SupportTicket)
            .where(
                SupportTicket.conversation_id == conversation_id,
                SupportTicket.status.in_(
                    [TicketStatus.OPEN, TicketStatus.IN_PROGRESS, TicketStatus.PENDING_CUSTOMER]
                ),
            )
            .order_by(SupportTicket.created_at.desc())
            .limit(1)
        )
        return (await self._session.execute(stmt)).scalar_one_or_none()

    async def count_created_since(self, customer_id: uuid.UUID, since: datetime) -> int:
        stmt = (
            select(func.count())
            .select_from(SupportTicket)
            .where(SupportTicket.customer_id == customer_id, SupportTicket.created_at >= since)
        )
        return int((await self._session.execute(stmt)).scalar_one())

    async def list_for_customer(
        self, customer_id: uuid.UUID, *, limit: int, offset: int
    ) -> list[SupportTicket]:
        limit, offset = clamp_page(limit, offset)
        stmt = (
            select(SupportTicket)
            .where(SupportTicket.customer_id == customer_id)
            .order_by(SupportTicket.created_at.desc(), SupportTicket.id)
            .limit(limit)
            .offset(offset)
        )
        return list((await self._session.execute(stmt)).scalars())

    async def list_all(
        self,
        *,
        status: TicketStatus | None,
        priority: Priority | None,
        assigned_to: uuid.UUID | None,
        limit: int,
        offset: int,
    ) -> list[SupportTicket]:
        limit, offset = clamp_page(limit, offset)
        stmt = select(SupportTicket)
        if status is not None:
            stmt = stmt.where(SupportTicket.status == status)
        if priority is not None:
            stmt = stmt.where(SupportTicket.priority == priority)
        if assigned_to is not None:
            stmt = stmt.where(SupportTicket.assigned_to_user_id == assigned_to)
        stmt = (
            stmt.order_by(SupportTicket.created_at.desc(), SupportTicket.id)
            .limit(limit)
            .offset(offset)
        )
        return list((await self._session.execute(stmt)).scalars())


class PendingActionRepository:
    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    def add(self, action: PendingAction) -> PendingAction:
        self._session.add(action)
        return action

    async def get_for_user(
        self, action_id: uuid.UUID, *, conversation_id: uuid.UUID, user_id: uuid.UUID
    ) -> PendingAction | None:
        stmt = select(PendingAction).where(
            PendingAction.id == action_id,
            PendingAction.conversation_id == conversation_id,
            PendingAction.user_id == user_id,
        )
        return (await self._session.execute(stmt)).scalar_one_or_none()

    async def get_open_by_dedupe(self, dedupe_key: str) -> PendingAction | None:
        stmt = select(PendingAction).where(
            PendingAction.dedupe_key == dedupe_key,
            PendingAction.status.in_([ActionStatus.PENDING, ActionStatus.EXECUTING]),
        )
        return (await self._session.execute(stmt)).scalar_one_or_none()

    async def claim_for_execution(self, action_id: uuid.UUID, now: datetime) -> bool:
        """Atomic PENDING -> EXECUTING transition: exactly one confirmation can win."""
        result = await self._session.execute(
            update(PendingAction)
            .where(
                PendingAction.id == action_id,
                PendingAction.status == ActionStatus.PENDING,
                PendingAction.expires_at > now,
            )
            .values(status=ActionStatus.EXECUTING, decided_at=now)
        )
        return affected_rows(result) == 1

    async def list_for_conversation(
        self, conversation_id: uuid.UUID, *, limit: int = 20
    ) -> list[PendingAction]:
        stmt = (
            select(PendingAction)
            .where(PendingAction.conversation_id == conversation_id)
            .order_by(PendingAction.created_at.desc(), PendingAction.id)
            .limit(max(1, min(limit, 100)))
        )
        return list((await self._session.execute(stmt)).scalars())

    async def expire_stale(self, now: datetime) -> int:
        result = await self._session.execute(
            update(PendingAction)
            .where(PendingAction.status == ActionStatus.PENDING, PendingAction.expires_at <= now)
            .values(status=ActionStatus.EXPIRED, decided_at=now)
        )
        return affected_rows(result)
