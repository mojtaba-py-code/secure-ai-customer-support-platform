"""Support tickets."""

from __future__ import annotations

import uuid
from datetime import timedelta

from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from aegis.core.errors import Conflict, NotFound, PermissionDenied, RateLimited, ValidationFailed
from aegis.core.ids import reference_number
from aegis.core.time import Clock, utc_now
from aegis.domain.enums import AuditOutcome, Priority, RequestSource, TicketStatus
from aegis.models import SupportTicket
from aegis.repositories.identity import UserRepository
from aegis.repositories.support import TicketRepository
from aegis.security.principal import Principal
from aegis.security.rbac import Permission
from aegis.security.redaction import redact_for_storage
from aegis.security.text import normalize_text, truncate
from aegis.services.audit import AuditService
from aegis.services.authz import customer_scope, require

MAX_SUBJECT = 200
MAX_DESCRIPTION = 4_000


def clean_ticket_text(value: str, limit: int) -> str:
    return truncate(redact_for_storage(normalize_text(value)).text, limit)


class TicketService:
    def __init__(
        self,
        session: AsyncSession,
        *,
        audit: AuditService,
        max_per_day: int,
        clock: Clock = utc_now,
    ) -> None:
        self._session = session
        self._tickets = TicketRepository(session)
        self._users = UserRepository(session)
        self._audit = audit
        self._max_per_day = max_per_day
        self._clock = clock

    async def create(
        self,
        principal: Principal,
        *,
        subject: str,
        description: str,
        category: str,
        priority: Priority,
        source: RequestSource,
        conversation_id: uuid.UUID | None = None,
        idempotency_key: str | None = None,
    ) -> SupportTicket:
        require(principal, Permission.TICKET_CREATE_OWN)
        customer_id = principal.customer_id
        if customer_id is None:
            raise PermissionDenied
        if idempotency_key is not None:
            existing = await self._tickets.get_by_idempotency_key(idempotency_key)
            if existing is not None:
                if existing.customer_id != customer_id:
                    raise Conflict("This idempotency key is already in use.")
                return existing
        now = self._clock()
        if (
            await self._tickets.count_created_since(customer_id, now - timedelta(days=1))
            >= self._max_per_day
        ):
            raise RateLimited(3_600, "You have opened the maximum number of tickets for today.")
        subject_clean = clean_ticket_text(subject, MAX_SUBJECT)
        description_clean = clean_ticket_text(description, MAX_DESCRIPTION)
        if len(subject_clean) < 3 or len(description_clean) < 3:
            raise ValidationFailed("Please provide a subject and a description.")
        for _attempt in range(3):
            ticket = SupportTicket(
                ticket_number=reference_number("TCK"),
                customer_id=customer_id,
                conversation_id=conversation_id,
                created_by_user_id=principal.user_id,
                subject=subject_clean,
                description=description_clean,
                category=category[:40],
                priority=priority,
                status=TicketStatus.OPEN,
                source=source,
                idempotency_key=idempotency_key,
            )
            self._tickets.add(ticket)
            try:
                await self._session.commit()
            except IntegrityError:
                await self._session.rollback()
                if idempotency_key is not None:
                    raced = await self._tickets.get_by_idempotency_key(idempotency_key)
                    if raced is not None and raced.customer_id == customer_id:
                        return raced
                continue
            await self._audit.record(
                "ticket.create",
                outcome=AuditOutcome.SUCCESS,
                actor=principal,
                resource_type="ticket",
                resource_id=ticket.id,
                details={
                    "source": source.value,
                    "priority": priority.value,
                    "category": ticket.category,
                },
            )
            return ticket
        raise Conflict("The ticket could not be created. Please try again.")

    async def get(self, principal: Principal, ticket_id: uuid.UUID) -> SupportTicket:
        scope = customer_scope(
            principal, own=Permission.TICKET_READ_OWN, any_=Permission.TICKET_READ_ANY
        )
        ticket = (
            await self._tickets.get(ticket_id)
            if scope is None
            else await self._tickets.get_for_customer(scope, ticket_id)
        )
        if ticket is None:
            raise NotFound
        return ticket

    async def get_by_number(self, principal: Principal, ticket_number: str) -> SupportTicket:
        require(principal, Permission.TICKET_READ_OWN)
        if principal.customer_id is None:
            raise NotFound
        ticket = await self._tickets.get_by_number_for_customer(
            principal.customer_id, ticket_number
        )
        if ticket is None:
            raise NotFound("We could not find that ticket on your account.")
        return ticket

    async def list_tickets(
        self,
        principal: Principal,
        *,
        status: TicketStatus | None,
        priority: Priority | None,
        assigned_to_me: bool,
        limit: int,
        offset: int,
    ) -> list[SupportTicket]:
        scope = customer_scope(
            principal, own=Permission.TICKET_READ_OWN, any_=Permission.TICKET_READ_ANY
        )
        if scope is not None:
            return await self._tickets.list_for_customer(scope, limit=limit, offset=offset)
        return await self._tickets.list_all(
            status=status,
            priority=priority,
            assigned_to=principal.user_id if assigned_to_me else None,
            limit=limit,
            offset=offset,
        )

    async def update(
        self,
        principal: Principal,
        ticket_id: uuid.UUID,
        *,
        status: TicketStatus | None,
        priority: Priority | None,
        assigned_to_user_id: uuid.UUID | None,
    ) -> SupportTicket:
        require(principal, Permission.TICKET_UPDATE)
        ticket = await self._tickets.get(ticket_id)
        if ticket is None:
            raise NotFound
        changes: dict[str, object] = {}
        if assigned_to_user_id is not None and assigned_to_user_id != ticket.assigned_to_user_id:
            if assigned_to_user_id != principal.user_id:
                require(principal, Permission.HANDOFF_ASSIGN_ANY)
            assignee = await self._users.get(assigned_to_user_id)
            if assignee is None or not assignee.is_active or assignee.role.value == "customer":
                raise ValidationFailed("Tickets can only be assigned to active staff members.")
            ticket.assigned_to_user_id = assigned_to_user_id
            changes["assigned_to"] = str(assigned_to_user_id)
        if priority is not None and priority != ticket.priority:
            changes["priority"] = f"{ticket.priority.value}->{priority.value}"
            ticket.priority = priority
        if status is not None and status != ticket.status:
            changes["status"] = f"{ticket.status.value}->{status.value}"
            ticket.status = status
            if status in (TicketStatus.RESOLVED, TicketStatus.CLOSED):
                ticket.resolved_at = self._clock()
        await self._session.commit()
        if changes:
            await self._audit.record(
                "ticket.update",
                outcome=AuditOutcome.SUCCESS,
                actor=principal,
                resource_type="ticket",
                resource_id=ticket.id,
                details=changes,
            )
        return ticket
