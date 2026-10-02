"""Orders and refunds."""

from __future__ import annotations

import uuid
from typing import Annotated

from fastapi import APIRouter, Depends, Path, Query

from aegis.api.deps import Limit, Offset, PrincipalDep, ServicesDep, require
from aegis.api.v1 import API_V1_PREFIX
from aegis.bootstrap import RequestServices
from aegis.domain.enums import RefundStatus
from aegis.domain.identifiers import ORDER_NUMBER_PATTERN
from aegis.models import Order, Refund
from aegis.schemas.commerce import (
    OrderItemOut,
    OrderOut,
    OrderSummaryOut,
    PaymentOut,
    RefundDecision,
    RefundOut,
)
from aegis.schemas.common import Page
from aegis.security.principal import Principal
from aegis.security.rbac import Permission
from aegis.services.commerce import latest_payment

orders_router = APIRouter(prefix=f"{API_V1_PREFIX}/orders", tags=["orders"])
refunds_router = APIRouter(prefix=f"{API_V1_PREFIX}/refunds", tags=["refunds"])

OrderNumber = Annotated[str, Path(pattern=ORDER_NUMBER_PATTERN, max_length=16)]
Decider = Annotated[Principal, Depends(require(Permission.REFUND_DECIDE))]


def _order_out(order: Order) -> OrderOut:
    payment = latest_payment(order)
    return OrderOut(
        order_number=order.order_number,
        status=order.status,
        placed_at=order.placed_at,
        total_cents=order.total_cents,
        currency=order.currency,
        subtotal_cents=order.subtotal_cents,
        shipping_cents=order.shipping_cents,
        shipped_at=order.shipped_at,
        delivered_at=order.delivered_at,
        cancelled_at=order.cancelled_at,
        estimated_delivery=order.estimated_delivery,
        carrier=order.carrier,
        tracking_number=order.tracking_number,
        items=[OrderItemOut.model_validate(item) for item in order.items],
        payment=PaymentOut.model_validate(payment) if payment else None,
    )


@orders_router.get("", response_model=Page[OrderSummaryOut])
async def list_orders(
    principal: PrincipalDep,
    services: ServicesDep,
    limit: Limit = 20,
    offset: Offset = 0,
    customer_id: Annotated[
        uuid.UUID | None, Query(description="Staff only: filter by customer")
    ] = None,
) -> Page[OrderSummaryOut]:
    orders = await services.orders.list_orders(
        principal, limit=limit, offset=offset, customer_id=customer_id
    )
    return Page[OrderSummaryOut](
        items=[OrderSummaryOut.model_validate(o) for o in orders], limit=limit, offset=offset
    )


@orders_router.get("/{order_number}", response_model=OrderOut)
async def get_order(
    order_number: OrderNumber, principal: PrincipalDep, services: ServicesDep
) -> OrderOut:
    return _order_out(await services.orders.get_order(principal, order_number))


async def _refund_out(services: RequestServices, refund: Refund) -> RefundOut:
    return RefundOut(
        id=refund.id,
        refund_number=refund.refund_number,
        order_number=await services.refunds.order_number(refund),
        amount_cents=refund.amount_cents,
        currency=refund.currency,
        status=refund.status,
        reason=refund.reason,
        source=refund.source,
        created_at=refund.created_at,
        reviewed_at=refund.reviewed_at,
        completed_at=refund.completed_at,
    )


@refunds_router.get("", response_model=Page[RefundOut])
async def list_refunds(
    principal: PrincipalDep,
    services: ServicesDep,
    status: RefundStatus | None = None,
    limit: Limit = 20,
    offset: Offset = 0,
) -> Page[RefundOut]:
    refunds = await services.refunds.list_refunds(
        principal, status=status, limit=limit, offset=offset
    )
    return Page[RefundOut](
        items=[await _refund_out(services, r) for r in refunds], limit=limit, offset=offset
    )


@refunds_router.get("/{refund_id}", response_model=RefundOut)
async def get_refund(
    refund_id: uuid.UUID, principal: PrincipalDep, services: ServicesDep
) -> RefundOut:
    return await _refund_out(services, await services.refunds.get(principal, refund_id))


@refunds_router.post("/{refund_id}/decision", response_model=RefundOut)
async def decide_refund(
    refund_id: uuid.UUID, body: RefundDecision, principal: Decider, services: ServicesDep
) -> RefundOut:
    """Approve (executes the refund with the payment provider) or reject. Managers only."""
    refund = await services.refunds.decide(
        principal, refund_id, approve=body.approve, note=body.note
    )
    return await _refund_out(services, refund)
