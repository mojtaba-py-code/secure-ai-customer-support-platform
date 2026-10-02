"""Data-subject request schemas: the personal-data export and erasure."""

from __future__ import annotations

import uuid
from datetime import datetime

from pydantic import Field

from aegis.domain.enums import (
    ConversationStatus,
    CustomerTier,
    OrderStatus,
    PaymentMethod,
    PaymentStatus,
    Priority,
    RefundReason,
    RefundStatus,
    Role,
    SenderType,
    TicketStatus,
)
from aegis.schemas.common import RequestModel, ResponseModel


class ExportCustomer(ResponseModel):
    customer_number: str
    full_name: str
    email: str
    phone: str | None
    address: str | None
    tier: CustomerTier
    created_at: datetime


class ExportAccount(ResponseModel):
    email: str
    display_name: str
    role: Role
    created_at: datetime
    last_login_at: datetime | None
    two_factor_enabled: bool


class ExportOrderItem(ResponseModel):
    sku: str
    product_name: str
    quantity: int
    unit_price_cents: int


class ExportPayment(ResponseModel):
    status: PaymentStatus
    method: PaymentMethod
    amount_cents: int
    currency: str
    card_brand: str | None
    card_last4: str | None
    created_at: datetime


class ExportOrder(ResponseModel):
    order_number: str
    status: OrderStatus
    placed_at: datetime
    currency: str
    subtotal_cents: int
    shipping_cents: int
    total_cents: int
    shipping_address: str | None
    carrier: str | None
    tracking_number: str | None
    items: list[ExportOrderItem]
    payments: list[ExportPayment]


class ExportRefund(ResponseModel):
    refund_number: str
    order_number: str
    status: RefundStatus
    amount_cents: int
    currency: str
    reason: RefundReason
    customer_note: str | None
    created_at: datetime
    completed_at: datetime | None


class ExportMessage(ResponseModel):
    sender_type: SenderType
    content: str
    created_at: datetime


class ExportConversation(ResponseModel):
    id: uuid.UUID
    subject: str | None
    status: ConversationStatus
    created_at: datetime
    messages: list[ExportMessage]


class ExportTicket(ResponseModel):
    ticket_number: str
    subject: str
    description: str
    category: str
    priority: Priority
    status: TicketStatus
    created_at: datetime
    resolved_at: datetime | None


class PrivacyExport(ResponseModel):
    """Everything the platform stores about the signed-in customer."""

    generated_at: datetime
    customer: ExportCustomer
    accounts: list[ExportAccount]
    orders: list[ExportOrder]
    refunds: list[ExportRefund]
    conversations: list[ExportConversation]
    tickets: list[ExportTicket]


class ErasureRequestOut(ResponseModel):
    ticket_number: str
    detail: str


class ErasureConfirmation(RequestModel):
    customer_number: str = Field(
        min_length=5, max_length=16, description="Type the customer number to confirm."
    )


class ErasureReportOut(ResponseModel):
    customer_id: uuid.UUID
    erased_at: datetime
    counts: dict[str, int]
