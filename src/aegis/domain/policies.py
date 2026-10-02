"""Deterministic business policies.

Eligibility decisions are made here, in code, never by the language model: the model can ask
"is this order refundable?" through a tool, but the answer (and every amount in it) comes from
these functions and the database. The same functions are re-run at execution time, so a
decision cannot be stale when a customer confirms an action minutes later.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta

from aegis.domain.enums import (
    OPEN_REFUND_STATUSES,
    OrderStatus,
    PaymentStatus,
    RefundStatus,
)

REFUND_WINDOW_DAYS = 30
CANCELLABLE_STATUSES: frozenset[OrderStatus] = frozenset(
    {OrderStatus.PENDING, OrderStatus.PAID, OrderStatus.PROCESSING}
)
REFUNDABLE_PAYMENT_STATUSES: frozenset[PaymentStatus] = frozenset(
    {PaymentStatus.CAPTURED, PaymentStatus.PARTIALLY_REFUNDED}
)


@dataclass(frozen=True, slots=True)
class OrderFacts:
    status: OrderStatus
    total_cents: int
    delivered_at: datetime | None


@dataclass(frozen=True, slots=True)
class PaymentFacts:
    status: PaymentStatus
    amount_cents: int


@dataclass(frozen=True, slots=True)
class RefundFacts:
    status: RefundStatus
    amount_cents: int


@dataclass(frozen=True, slots=True)
class RefundEligibility:
    eligible: bool
    reasons: tuple[str, ...]
    max_refundable_cents: int
    window_ends_at: datetime | None = None
    notes: tuple[str, ...] = field(default_factory=tuple)


def evaluate_refund_eligibility(
    order: OrderFacts,
    payment: PaymentFacts | None,
    refunds: list[RefundFacts],
    *,
    now: datetime,
    window_days: int = REFUND_WINDOW_DAYS,
) -> RefundEligibility:
    """Apply the published refund policy to one order.

    Reason codes (stable, machine readable): ``not_delivered``, ``window_expired``,
    ``order_cancelled``, ``no_captured_payment``, ``refund_in_progress``, ``fully_refunded``.
    """
    reasons: list[str] = []
    window_end: datetime | None = None

    if order.status is OrderStatus.CANCELLED:
        reasons.append("order_cancelled")
    elif order.status is not OrderStatus.DELIVERED or order.delivered_at is None:
        reasons.append("not_delivered")
    else:
        window_end = order.delivered_at + timedelta(days=window_days)
        if now > window_end:
            reasons.append("window_expired")

    if payment is None or payment.status not in REFUNDABLE_PAYMENT_STATUSES:
        reasons.append("no_captured_payment")

    if any(r.status in OPEN_REFUND_STATUSES for r in refunds):
        reasons.append("refund_in_progress")

    refunded = sum(r.amount_cents for r in refunds if r.status is RefundStatus.COMPLETED)
    captured = payment.amount_cents if payment is not None else 0
    remaining = max(0, min(captured, order.total_cents) - refunded)
    if payment is not None and remaining == 0 and "no_captured_payment" not in reasons:
        reasons.append("fully_refunded")

    eligible = not reasons
    return RefundEligibility(
        eligible=eligible,
        reasons=tuple(reasons),
        max_refundable_cents=remaining if eligible else 0,
        window_ends_at=window_end,
    )


def can_cancel_order(status: OrderStatus) -> bool:
    return status in CANCELLABLE_STATUSES


def cancellation_blockers(status: OrderStatus) -> tuple[str, ...]:
    if status in CANCELLABLE_STATUSES:
        return ()
    if status is OrderStatus.CANCELLED:
        return ("already_cancelled",)
    if status in (OrderStatus.SHIPPED, OrderStatus.DELIVERED):
        return ("already_shipped",)
    return ("not_cancellable",)
