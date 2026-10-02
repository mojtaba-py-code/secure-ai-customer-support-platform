"""Order, payment, refund and ticket schemas (payment data is masked)."""

from __future__ import annotations

import uuid
from datetime import date, datetime
from typing import Annotated

from pydantic import StrictBool, StringConstraints

from aegis.domain.enums import (
    OrderStatus,
    PaymentMethod,
    PaymentStatus,
    Priority,
    RefundReason,
    RefundStatus,
    RequestSource,
    TicketStatus,
)
from aegis.schemas.common import RequestModel, ResponseModel


class OrderItemOut(ResponseModel):
    sku: str
    product_name: str
    quantity: int
    unit_price_cents: int


class PaymentOut(ResponseModel):
    status: PaymentStatus
    method: PaymentMethod
    amount_cents: int
    currency: str
    card_brand: str | None
    card_last4: str | None
    captured_at: datetime | None


class OrderSummaryOut(ResponseModel):
    order_number: str
    status: OrderStatus
    placed_at: datetime
    total_cents: int
    currency: str


class OrderOut(OrderSummaryOut):
    subtotal_cents: int
    shipping_cents: int
    shipped_at: datetime | None
    delivered_at: datetime | None
    cancelled_at: datetime | None
    estimated_delivery: date | None
    carrier: str | None
    tracking_number: str | None
    items: list[OrderItemOut]
    payment: PaymentOut | None


class RefundOut(ResponseModel):
    id: uuid.UUID
    refund_number: str
    order_number: str
    amount_cents: int
    currency: str
    status: RefundStatus
    reason: RefundReason
    source: RequestSource
    created_at: datetime
    reviewed_at: datetime | None
    completed_at: datetime | None


class RefundDecision(RequestModel):
    approve: StrictBool  # a JSON boolean: 1, "yes" or "true" do not approve a refund
    note: Annotated[str, StringConstraints(max_length=500)] | None = None


TicketCategory = Annotated[str, StringConstraints(pattern=r"^[a-z_]{3,40}$")]


class TicketCreate(RequestModel):
    subject: Annotated[str, StringConstraints(min_length=3, max_length=200)]
    description: Annotated[str, StringConstraints(min_length=10, max_length=4_000)]
    category: TicketCategory = "general_question"
    priority: Priority = Priority.MEDIUM


class TicketUpdate(RequestModel):
    status: TicketStatus | None = None
    priority: Priority | None = None
    assigned_to_user_id: uuid.UUID | None = None


class TicketOut(ResponseModel):
    id: uuid.UUID
    ticket_number: str
    subject: str
    description: str
    category: str
    priority: Priority
    status: TicketStatus
    source: RequestSource
    conversation_id: uuid.UUID | None
    assigned_to_user_id: uuid.UUID | None
    created_at: datetime
    updated_at: datetime
    resolved_at: datetime | None


class WebhookAck(ResponseModel):
    received: bool
    result: str
