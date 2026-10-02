"""The simulated commerce system: customers, catalogue, orders, payments and refunds.

Integrity rules live in the schema as well as in code (defence in depth): amounts are
non-negative, totals add up, a card is stored only as brand + last four digits (never the
PAN), and at most one refund per order can be open at a time (partial unique index), which
makes duplicate refunds impossible even under concurrent requests.
"""

from __future__ import annotations

import uuid
from datetime import date, datetime

from sqlalchemy import (
    Boolean,
    CheckConstraint,
    Date,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    text,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from aegis.core.time import utc_now
from aegis.db.base import Base, EncryptedText, TimestampMixin, UUIDPrimaryKeyMixin, str_enum
from aegis.domain.enums import (
    CustomerTier,
    OrderStatus,
    PaymentMethod,
    PaymentStatus,
    RefundReason,
    RefundStatus,
    RequestSource,
    StockStatus,
)

OPEN_REFUND_SQL = "status IN ('pending_review', 'approved', 'processing')"


class Customer(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    __tablename__ = "customers"

    customer_number: Mapped[str] = mapped_column(String(16), unique=True)
    full_name: Mapped[str] = mapped_column(String(120))
    email: Mapped[str] = mapped_column(String(254), unique=True)
    phone: Mapped[str | None] = mapped_column(EncryptedText())
    address: Mapped[str | None] = mapped_column(EncryptedText())
    #: Set when the customer's personal data was erased (anonymised) on request.
    erased_at: Mapped[datetime | None]
    tier: Mapped[CustomerTier] = mapped_column(
        str_enum(CustomerTier, "tier"), default=CustomerTier.STANDARD
    )

    __table_args__ = (CheckConstraint("email = lower(email)", name="email_lowercase"),)


class Product(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    __tablename__ = "products"

    sku: Mapped[str] = mapped_column(String(32), unique=True)
    name: Mapped[str] = mapped_column(String(160))
    category: Mapped[str] = mapped_column(String(60), index=True)
    description: Mapped[str] = mapped_column(Text)
    price_cents: Mapped[int] = mapped_column(Integer)
    currency: Mapped[str] = mapped_column(String(3), default="USD")
    warranty_months: Mapped[int] = mapped_column(Integer, default=12)
    stock_status: Mapped[StockStatus] = mapped_column(
        str_enum(StockStatus, "stock_status"), default=StockStatus.IN_STOCK
    )
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)

    __table_args__ = (
        CheckConstraint("price_cents >= 0", name="price_non_negative"),
        CheckConstraint("warranty_months >= 0", name="warranty_non_negative"),
    )


class Order(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    __tablename__ = "orders"

    order_number: Mapped[str] = mapped_column(String(16), unique=True)
    customer_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("customers.id", ondelete="RESTRICT"))
    status: Mapped[OrderStatus] = mapped_column(str_enum(OrderStatus, "order_status"))
    currency: Mapped[str] = mapped_column(String(3), default="USD")
    subtotal_cents: Mapped[int] = mapped_column(Integer)
    shipping_cents: Mapped[int] = mapped_column(Integer, default=0)
    total_cents: Mapped[int] = mapped_column(Integer)
    placed_at: Mapped[datetime]
    shipped_at: Mapped[datetime | None]
    delivered_at: Mapped[datetime | None]
    cancelled_at: Mapped[datetime | None]
    carrier: Mapped[str | None] = mapped_column(String(40))
    tracking_number: Mapped[str | None] = mapped_column(String(64))
    estimated_delivery: Mapped[date | None] = mapped_column(Date)
    shipping_address: Mapped[str | None] = mapped_column(EncryptedText())

    items: Mapped[list[OrderItem]] = relationship(
        back_populates="order",
        lazy="raise",
        cascade="all, delete-orphan",
        order_by="OrderItem.position",
    )
    payments: Mapped[list[Payment]] = relationship(back_populates="order", lazy="raise")

    __table_args__ = (
        CheckConstraint("subtotal_cents >= 0 AND shipping_cents >= 0", name="amounts_non_negative"),
        CheckConstraint("total_cents = subtotal_cents + shipping_cents", name="total_consistent"),
        Index("ix_orders_customer_placed", "customer_id", "placed_at"),
    )


class OrderItem(UUIDPrimaryKeyMixin, Base):
    __tablename__ = "order_items"

    order_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("orders.id", ondelete="CASCADE"), index=True
    )
    product_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("products.id", ondelete="SET NULL")
    )
    position: Mapped[int] = mapped_column(Integer, default=1)
    sku: Mapped[str] = mapped_column(String(32))
    product_name: Mapped[str] = mapped_column(String(160))
    quantity: Mapped[int] = mapped_column(Integer)
    unit_price_cents: Mapped[int] = mapped_column(Integer)

    order: Mapped[Order] = relationship(back_populates="items", lazy="raise")

    __table_args__ = (
        CheckConstraint("quantity > 0", name="quantity_positive"),
        CheckConstraint("unit_price_cents >= 0", name="unit_price_non_negative"),
    )


class Payment(UUIDPrimaryKeyMixin, Base):
    __tablename__ = "payments"

    order_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("orders.id", ondelete="RESTRICT"), index=True
    )
    status: Mapped[PaymentStatus] = mapped_column(str_enum(PaymentStatus, "payment_status"))
    method: Mapped[PaymentMethod] = mapped_column(str_enum(PaymentMethod, "payment_method"))
    amount_cents: Mapped[int] = mapped_column(Integer)
    currency: Mapped[str] = mapped_column(String(3), default="USD")
    card_brand: Mapped[str | None] = mapped_column(String(20))
    card_last4: Mapped[str | None] = mapped_column(String(4))
    provider_reference: Mapped[str] = mapped_column(String(64), unique=True)
    failure_code: Mapped[str | None] = mapped_column(String(40))
    created_at: Mapped[datetime] = mapped_column(default=utc_now)
    captured_at: Mapped[datetime | None]

    order: Mapped[Order] = relationship(back_populates="payments", lazy="raise")

    __table_args__ = (
        CheckConstraint("amount_cents > 0", name="amount_positive"),
        CheckConstraint("card_last4 IS NULL OR length(card_last4) = 4", name="card_last4_only"),
    )


class Refund(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    __tablename__ = "refunds"

    refund_number: Mapped[str] = mapped_column(String(16), unique=True)
    order_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("orders.id", ondelete="RESTRICT"), index=True
    )
    payment_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("payments.id", ondelete="RESTRICT"))
    amount_cents: Mapped[int] = mapped_column(Integer)
    currency: Mapped[str] = mapped_column(String(3), default="USD")
    status: Mapped[RefundStatus] = mapped_column(str_enum(RefundStatus, "refund_status"))
    reason: Mapped[RefundReason] = mapped_column(str_enum(RefundReason, "refund_reason"))
    customer_note: Mapped[str | None] = mapped_column(EncryptedText())
    source: Mapped[RequestSource] = mapped_column(str_enum(RequestSource, "refund_source"))
    requested_by_user_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL")
    )
    reviewed_by_user_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL")
    )
    reviewed_at: Mapped[datetime | None]
    decision_note: Mapped[str | None] = mapped_column(String(500))
    completed_at: Mapped[datetime | None]
    idempotency_key: Mapped[str | None] = mapped_column(String(120), unique=True)
    #: The payment provider's refund id (for example Stripe's ``re_...``), set when submitted.
    provider_refund_id: Mapped[str | None] = mapped_column(String(64), unique=True)

    __table_args__ = (
        CheckConstraint("amount_cents > 0", name="amount_positive"),
        Index(
            "uq_refunds_one_open_per_order",
            "order_id",
            unique=True,
            postgresql_where=text(OPEN_REFUND_SQL),
            sqlite_where=text(OPEN_REFUND_SQL),
        ),
    )
