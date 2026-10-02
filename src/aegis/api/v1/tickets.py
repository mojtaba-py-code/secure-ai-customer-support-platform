"""Support tickets."""

from __future__ import annotations

import uuid
from typing import Annotated

from fastapi import APIRouter, Depends, Query, status

from aegis.api.deps import IdempotencyKeyDep, Limit, Offset, PrincipalDep, ServicesDep, require
from aegis.api.v1 import API_V1_PREFIX
from aegis.domain.enums import Priority, RequestSource, TicketStatus
from aegis.schemas.commerce import TicketCreate, TicketOut, TicketUpdate
from aegis.schemas.common import Page
from aegis.security.principal import Principal
from aegis.security.rbac import Permission
from aegis.services.idempotency import request_fingerprint

router = APIRouter(prefix=f"{API_V1_PREFIX}/support/tickets", tags=["tickets"])

Creator = Annotated[Principal, Depends(require(Permission.TICKET_CREATE_OWN))]
Updater = Annotated[Principal, Depends(require(Permission.TICKET_UPDATE))]
_CUSTOMER_PRIORITIES = (Priority.LOW, Priority.MEDIUM, Priority.HIGH)


@router.post("", status_code=status.HTTP_201_CREATED, response_model=TicketOut)
async def create_ticket(
    body: TicketCreate,
    principal: Creator,
    services: ServicesDep,
    idempotency_key: IdempotencyKeyDep,
) -> TicketOut:
    """Open a ticket. ``Idempotency-Key`` makes retries safe (no duplicate tickets)."""
    record_id = None
    if idempotency_key is not None:
        ticket_hold = await services.idempotency.begin(
            user_id=principal.user_id,
            scope="ticket",
            key=idempotency_key,
            request_hash=request_fingerprint(body.model_dump()),
        )
        if ticket_hold.replay_resource_id is not None:
            return TicketOut.model_validate(
                await services.tickets.get(principal, uuid.UUID(ticket_hold.replay_resource_id))
            )
        record_id = ticket_hold.record_id
    try:
        ticket = await services.tickets.create(
            principal,
            subject=body.subject,
            description=body.description,
            category=body.category,
            # Customers cannot self-assign "urgent"; urgency is decided by staff or by policy.
            priority=body.priority if body.priority in _CUSTOMER_PRIORITIES else Priority.HIGH,
            source=RequestSource.CUSTOMER,
        )
    except Exception:
        if record_id is not None:
            await services.idempotency.release(record_id)
        raise
    if record_id is not None:
        await services.idempotency.complete(record_id, str(ticket.id))
    return TicketOut.model_validate(ticket)


@router.get("", response_model=Page[TicketOut])
async def list_tickets(
    principal: PrincipalDep,
    services: ServicesDep,
    status_filter: Annotated[TicketStatus | None, Query(alias="status")] = None,
    priority: Priority | None = None,
    assigned_to_me: bool = False,
    limit: Limit = 20,
    offset: Offset = 0,
) -> Page[TicketOut]:
    tickets = await services.tickets.list_tickets(
        principal,
        status=status_filter,
        priority=priority,
        assigned_to_me=assigned_to_me,
        limit=limit,
        offset=offset,
    )
    return Page[TicketOut](
        items=[TicketOut.model_validate(t) for t in tickets], limit=limit, offset=offset
    )


@router.get("/{ticket_id}", response_model=TicketOut)
async def get_ticket(
    ticket_id: uuid.UUID, principal: PrincipalDep, services: ServicesDep
) -> TicketOut:
    return TicketOut.model_validate(await services.tickets.get(principal, ticket_id))


@router.patch("/{ticket_id}", response_model=TicketOut)
async def update_ticket(
    ticket_id: uuid.UUID, body: TicketUpdate, principal: Updater, services: ServicesDep
) -> TicketOut:
    ticket = await services.tickets.update(
        principal,
        ticket_id,
        status=body.status,
        priority=body.priority,
        assigned_to_user_id=body.assigned_to_user_id,
    )
    return TicketOut.model_validate(ticket)
