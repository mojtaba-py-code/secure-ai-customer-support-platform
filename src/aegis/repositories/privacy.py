"""Queries for data-subject requests: a complete export and irreversible anonymisation."""

from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import delete, select, update
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from aegis.domain.enums import (
    OPEN_REFUND_STATUSES,
    ActionStatus,
    ConversationStatus,
    OrderStatus,
    TicketStatus,
)
from aegis.models import (
    Conversation,
    Customer,
    IdempotencyRecord,
    Message,
    Order,
    PendingAction,
    Refund,
    SupportTicket,
    User,
)
from aegis.repositories.common import affected_rows

ACTIVE_ORDER_STATUSES = (
    OrderStatus.PENDING,
    OrderStatus.PAID,
    OrderStatus.PROCESSING,
    OrderStatus.SHIPPED,
)
FINISHED_CONVERSATION_STATUSES = (ConversationStatus.RESOLVED, ConversationStatus.CLOSED)


class PrivacyRepository:
    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    # --- export ------------------------------------------------------------------------------------
    async def customer(
        self, customer_id: uuid.UUID, *, for_update: bool = False
    ) -> Customer | None:
        stmt = select(Customer).where(Customer.id == customer_id)
        if for_update:
            stmt = stmt.with_for_update().execution_options(populate_existing=True)
        return (await self._session.execute(stmt)).scalar_one_or_none()

    async def users(self, customer_id: uuid.UUID) -> list[User]:
        stmt = select(User).where(User.customer_id == customer_id)
        return list((await self._session.execute(stmt)).scalars())

    async def orders(self, customer_id: uuid.UUID) -> list[Order]:
        stmt = (
            select(Order)
            .options(selectinload(Order.items), selectinload(Order.payments))
            .where(Order.customer_id == customer_id)
            .order_by(Order.placed_at, Order.id)
        )
        return list((await self._session.execute(stmt)).scalars())

    async def refunds(self, customer_id: uuid.UUID) -> list[Refund]:
        stmt = (
            select(Refund)
            .join(Order, Order.id == Refund.order_id)
            .where(Order.customer_id == customer_id)
            .order_by(Refund.created_at, Refund.id)
        )
        return list((await self._session.execute(stmt)).scalars())

    async def conversations(self, customer_id: uuid.UUID) -> list[Conversation]:
        stmt = (
            select(Conversation)
            .where(Conversation.customer_id == customer_id)
            .order_by(Conversation.created_at, Conversation.id)
        )
        return list((await self._session.execute(stmt)).scalars())

    async def messages(self, conversation_ids: list[uuid.UUID]) -> list[Message]:
        if not conversation_ids:
            return []
        stmt = (
            select(Message)
            .where(Message.conversation_id.in_(conversation_ids))
            .order_by(Message.conversation_id, Message.sequence)
        )
        return list((await self._session.execute(stmt)).scalars())

    async def tickets(self, customer_id: uuid.UUID) -> list[SupportTicket]:
        stmt = (
            select(SupportTicket)
            .where(SupportTicket.customer_id == customer_id)
            .order_by(SupportTicket.created_at, SupportTicket.id)
        )
        return list((await self._session.execute(stmt)).scalars())

    # --- erasure -----------------------------------------------------------------------------------
    async def blocking_activity(self, customer_id: uuid.UUID) -> list[str]:
        """Reasons the customer's data cannot be erased yet (work that still needs it)."""
        reasons = []
        active_order = await self._session.execute(
            select(Order.id)
            .where(Order.customer_id == customer_id, Order.status.in_(ACTIVE_ORDER_STATUSES))
            .limit(1)
        )
        if active_order.first() is not None:
            reasons.append("orders_in_progress")
        open_refund = await self._session.execute(
            select(Refund.id)
            .join(Order, Order.id == Refund.order_id)
            .where(Order.customer_id == customer_id, Refund.status.in_(OPEN_REFUND_STATUSES))
            .limit(1)
        )
        if open_refund.first() is not None:
            reasons.append("refunds_in_progress")
        executing = await self._session.execute(
            select(PendingAction.id)
            .where(
                PendingAction.customer_id == customer_id,
                PendingAction.status == ActionStatus.EXECUTING,
            )
            .limit(1)
        )
        if executing.first() is not None:
            reasons.append("actions_in_progress")
        return reasons

    async def anonymise_records(
        self, customer_id: uuid.UUID, *, now: datetime, placeholder: str
    ) -> dict[str, int]:
        """Blank the free text and contact data around a customer, keeping financial records."""
        order_ids = select(Order.id).where(Order.customer_id == customer_id).scalar_subquery()
        conversation_ids = (
            select(Conversation.id).where(Conversation.customer_id == customer_id).scalar_subquery()
        )
        counts: dict[str, int] = {}
        counts["orders"] = affected_rows(
            await self._session.execute(
                update(Order).where(Order.customer_id == customer_id).values(shipping_address=None)
            )
        )
        counts["refunds"] = affected_rows(
            await self._session.execute(
                update(Refund).where(Refund.order_id.in_(order_ids)).values(customer_note=None)
            )
        )
        counts["messages"] = affected_rows(
            await self._session.execute(
                update(Message)
                .where(Message.conversation_id.in_(conversation_ids))
                .values(content=placeholder, meta={})
            )
        )
        counts["conversations"] = affected_rows(
            await self._session.execute(
                update(Conversation)
                .where(Conversation.customer_id == customer_id)
                .values(subject=None, summary=None, content_erased_at=now)
            )
        )
        await self._session.execute(
            update(Conversation)
            .where(
                Conversation.customer_id == customer_id,
                Conversation.status.not_in(FINISHED_CONVERSATION_STATUSES),
            )
            .values(status=ConversationStatus.CLOSED, closed_at=now)
        )
        counts["tickets"] = affected_rows(
            await self._session.execute(
                update(SupportTicket)
                .where(SupportTicket.customer_id == customer_id)
                .values(subject=placeholder, description=placeholder)
            )
        )
        await self._session.execute(
            update(SupportTicket)
            .where(
                SupportTicket.customer_id == customer_id,
                SupportTicket.status.not_in((TicketStatus.RESOLVED, TicketStatus.CLOSED)),
            )
            .values(status=TicketStatus.CLOSED, resolved_at=now)
        )
        counts["pending_actions"] = affected_rows(
            await self._session.execute(
                update(PendingAction)
                .where(
                    PendingAction.customer_id == customer_id,
                    PendingAction.status == ActionStatus.PENDING,
                )
                .values(status=ActionStatus.EXPIRED, decided_at=now)
            )
        )
        return counts

    async def delete_idempotency_records(self, user_id: uuid.UUID) -> None:
        await self._session.execute(
            delete(IdempotencyRecord).where(IdempotencyRecord.user_id == user_id)
        )

    # --- retention ---------------------------------------------------------------------------------
    async def expired_conversations(self, cutoff: datetime, *, limit: int) -> list[uuid.UUID]:
        stmt = (
            select(Conversation.id)
            .where(
                Conversation.status.in_(FINISHED_CONVERSATION_STATUSES),
                Conversation.last_message_at < cutoff,
                Conversation.content_erased_at.is_(None),
            )
            .order_by(Conversation.last_message_at)
            .limit(limit)
        )
        return list((await self._session.execute(stmt)).scalars())

    async def erase_conversation_text(
        self, conversation_ids: list[uuid.UUID], *, now: datetime, placeholder: str
    ) -> int:
        if not conversation_ids:
            return 0
        erased = affected_rows(
            await self._session.execute(
                update(Message)
                .where(Message.conversation_id.in_(conversation_ids))
                .values(content=placeholder, meta={})
            )
        )
        await self._session.execute(
            update(Conversation)
            .where(Conversation.id.in_(conversation_ids))
            .values(subject=None, summary=None, content_erased_at=now)
        )
        return erased
