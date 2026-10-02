"""Customers, catalogue, orders and refunds.

Authorisation pattern: every read resolves a *scope* from the caller's permissions - a customer
is pinned to their own ``customer_id`` in the SQL query, staff with ``*:read_any`` see all. A
record outside the scope is indistinguishable from a record that does not exist.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from datetime import datetime

from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from aegis.core.errors import Conflict, NotFound, ValidationFailed
from aegis.core.ids import reference_number
from aegis.core.time import Clock, utc_now
from aegis.domain.enums import (
    AuditOutcome,
    OrderStatus,
    PaymentStatus,
    RefundReason,
    RefundStatus,
    RequestSource,
)
from aegis.domain.policies import (
    OrderFacts,
    PaymentFacts,
    RefundEligibility,
    RefundFacts,
    cancellation_blockers,
    evaluate_refund_eligibility,
)
from aegis.models import Customer, Order, Payment, Product, Refund
from aegis.repositories.commerce import (
    CustomerRepository,
    OrderRepository,
    ProductRepository,
    RefundRepository,
)
from aegis.security.principal import Principal
from aegis.security.rbac import Permission
from aegis.security.redaction import redact_for_storage
from aegis.services.audit import AuditService
from aegis.services.authz import customer_scope, require
from aegis.services.payments import FAILED, PENDING, SUCCEEDED, PaymentGateway

ORDER_NOT_FOUND = "We could not find that order on your account."


def latest_payment(order: Order) -> Payment | None:
    if not order.payments:
        return None
    return max(order.payments, key=lambda p: (p.created_at, str(p.id)))


def settle_payment(payment: Payment, refunds: list[Refund]) -> None:
    """Payment status after a refund completed: refunded in full, or partially."""
    total = refunded_cents(refunds)
    if total >= payment.amount_cents:
        payment.status = PaymentStatus.REFUNDED
    elif total > 0:
        payment.status = PaymentStatus.PARTIALLY_REFUNDED


def refunded_cents(refunds: list[Refund]) -> int:
    return sum(r.amount_cents for r in refunds if r.status is RefundStatus.COMPLETED)


@dataclass(frozen=True, slots=True)
class CustomerSummary:
    first_name: str
    tier: str
    member_since: datetime
    order_count: int


class CustomerService:
    def __init__(self, session: AsyncSession) -> None:
        self._customers = CustomerRepository(session)

    async def summary(self, principal: Principal) -> CustomerSummary:
        if principal.customer_id is None:
            raise NotFound
        customer: Customer | None = await self._customers.get(principal.customer_id)
        if customer is None:
            raise NotFound
        return CustomerSummary(
            first_name=customer.full_name.split(" ")[0][:40],
            tier=customer.tier.value,
            member_since=customer.created_at,
            order_count=await self._customers.count_orders(customer.id),
        )


class ProductService:
    def __init__(self, session: AsyncSession) -> None:
        self._products = ProductRepository(session)

    async def lookup(
        self, principal: Principal, *, sku: str | None, query: str | None
    ) -> list[Product]:
        require(principal, Permission.PRODUCT_READ)
        if sku:
            product = await self._products.get_by_sku(sku)
            return [product] if product else []
        if query and len(query.strip()) >= 2:
            return await self._products.search(query[:80], limit=5)
        return []


class OrderService:
    def __init__(
        self,
        session: AsyncSession,
        *,
        audit: AuditService,
        gateway: PaymentGateway,
        clock: Clock = utc_now,
    ) -> None:
        self._session = session
        self._orders = OrderRepository(session)
        self._refunds = RefundRepository(session)
        self._audit = audit
        self._gateway = gateway
        self._clock = clock

    async def get_order(self, principal: Principal, order_number: str) -> Order:
        scope = customer_scope(
            principal, own=Permission.ORDER_READ_OWN, any_=Permission.ORDER_READ_ANY
        )
        if scope is None:
            order = await self._orders.get_by_number(order_number)
        else:
            order = await self._orders.get_for_customer(scope, order_number)
        if order is None:
            raise NotFound(ORDER_NOT_FOUND)
        return order

    async def list_orders(
        self, principal: Principal, *, limit: int, offset: int, customer_id: uuid.UUID | None = None
    ) -> list[Order]:
        scope = customer_scope(
            principal, own=Permission.ORDER_READ_OWN, any_=Permission.ORDER_READ_ANY
        )
        if scope is None:
            return await self._orders.list_all(customer_id=customer_id, limit=limit, offset=offset)
        return await self._orders.list_for_customer(scope, limit=limit, offset=offset)

    async def payment_status(
        self, principal: Principal, order_number: str
    ) -> tuple[Order, Payment | None]:
        customer_scope(principal, own=Permission.PAYMENT_READ_OWN, any_=Permission.PAYMENT_READ_ANY)
        order = await self.get_order(principal, order_number)
        return order, latest_payment(order)

    async def refunds_for_order(
        self, principal: Principal, order_number: str
    ) -> tuple[Order, list[Refund]]:
        customer_scope(principal, own=Permission.REFUND_READ_OWN, any_=Permission.REFUND_READ_ANY)
        order = await self.get_order(principal, order_number)
        return order, await self._refunds.list_for_order(order.id)

    async def refund_eligibility(
        self, principal: Principal, order_number: str
    ) -> tuple[Order, RefundEligibility]:
        order = await self.get_order(principal, order_number)
        refunds = await self._refunds.list_for_order(order.id)
        return order, self.evaluate(order, refunds)

    def evaluate(self, order: Order, refunds: list[Refund]) -> RefundEligibility:
        payment = latest_payment(order)
        return evaluate_refund_eligibility(
            OrderFacts(order.status, order.total_cents, order.delivered_at),
            PaymentFacts(payment.status, payment.amount_cents) if payment else None,
            [RefundFacts(r.status, r.amount_cents) for r in refunds],
            now=self._clock(),
        )

    async def locked_order_for_customer(self, customer_id: uuid.UUID, order_id: uuid.UUID) -> Order:
        order = await self._orders.get_for_update(order_id)
        if order is None or order.customer_id != customer_id:
            raise NotFound(ORDER_NOT_FOUND)
        return order

    async def cancel(self, principal: Principal, order: Order) -> dict[str, object]:
        """Cancel a locked order inside the caller's transaction (no commit here)."""
        require(principal, Permission.ORDER_CANCEL_OWN)
        blockers = cancellation_blockers(order.status)
        if blockers:
            raise Conflict(
                "This order can no longer be cancelled.", details={"reasons": list(blockers)}
            )
        now = self._clock()
        order.status = OrderStatus.CANCELLED
        order.cancelled_at = now
        payment = latest_payment(order)
        outcome: dict[str, object] = {
            "order_number": order.order_number,
            "status": order.status.value,
        }
        if payment is not None and payment.status is PaymentStatus.AUTHORIZED:
            payment.status = PaymentStatus.VOIDED
            outcome["payment"] = "authorization_voided"
        elif payment is not None and payment.status in (
            PaymentStatus.CAPTURED,
            PaymentStatus.PARTIALLY_REFUNDED,
        ):
            refunds = await self._refunds.list_for_order(order.id)
            amount = payment.amount_cents - refunded_cents(refunds)
            if amount > 0:
                refund = Refund(
                    refund_number=reference_number("RFD"),
                    order_id=order.id,
                    payment_id=payment.id,
                    amount_cents=amount,
                    currency=payment.currency,
                    status=RefundStatus.PROCESSING,
                    reason=RefundReason.ORDER_CANCELLED,
                    source=RequestSource.CUSTOMER,
                    requested_by_user_id=principal.user_id,
                    idempotency_key=f"cancel:{order.id}",
                )
                self._refunds.add(refund)
                result = await self._gateway.refund(
                    payment_reference=payment.provider_reference,
                    amount_cents=amount,
                    idempotency_key=refund.idempotency_key or str(refund.refund_number),
                    metadata={"aegis_refund_number": refund.refund_number},
                )
                refund.provider_refund_id = result.provider_refund_id
                if result.status == SUCCEEDED:
                    refund.status = RefundStatus.COMPLETED
                    refund.completed_at = now
                    payment.status = PaymentStatus.REFUNDED
                elif result.status == FAILED:
                    refund.status = RefundStatus.FAILED
                # PENDING stays PROCESSING until the provider's webhook reports the outcome.
                outcome["refund_number"] = refund.refund_number
                outcome["refund_amount_cents"] = amount
        return outcome


class RefundService:
    def __init__(
        self,
        session: AsyncSession,
        *,
        audit: AuditService,
        gateway: PaymentGateway,
        clock: Clock = utc_now,
    ) -> None:
        self._session = session
        self._refunds = RefundRepository(session)
        self._audit = audit
        self._gateway = gateway
        self._clock = clock

    def create_request(
        self,
        principal: Principal,
        *,
        order: Order,
        payment: Payment,
        amount_cents: int,
        reason: RefundReason,
        note: str | None,
        source: RequestSource,
        idempotency_key: str,
    ) -> Refund:
        """Stage a refund request (``pending_review``) in the caller's transaction."""
        require(principal, Permission.REFUND_REQUEST_OWN)
        if amount_cents <= 0:
            raise ValidationFailed("The refund amount must be positive.")
        refund = Refund(
            refund_number=reference_number("RFD"),
            order_id=order.id,
            payment_id=payment.id,
            amount_cents=amount_cents,
            currency=payment.currency,
            status=RefundStatus.PENDING_REVIEW,
            reason=reason,
            customer_note=redact_for_storage(note).text[:500] if note else None,
            source=source,
            requested_by_user_id=principal.user_id,
            idempotency_key=idempotency_key,
        )
        return self._refunds.add(refund)

    async def get(self, principal: Principal, refund_id: uuid.UUID) -> Refund:
        scope = customer_scope(
            principal, own=Permission.REFUND_READ_OWN, any_=Permission.REFUND_READ_ANY
        )
        refund = (
            await self._refunds.get(refund_id)
            if scope is None
            else await self._refunds.get_for_customer(scope, refund_id)
        )
        if refund is None:
            raise NotFound
        return refund

    async def list_refunds(
        self, principal: Principal, *, status: RefundStatus | None, limit: int, offset: int
    ) -> list[Refund]:
        scope = customer_scope(
            principal, own=Permission.REFUND_READ_OWN, any_=Permission.REFUND_READ_ANY
        )
        if scope is None:
            return await self._refunds.list_by_status(status, limit=limit, offset=offset)
        return await self._refunds.list_for_customer(scope, limit=limit, offset=offset)

    async def order_number(self, refund: Refund) -> str:
        return await self._refunds.order_number_for(refund)

    async def decide(
        self, principal: Principal, refund_id: uuid.UUID, *, approve: bool, note: str | None
    ) -> Refund:
        """Managers approve or reject; approval executes the refund through the payment gateway."""
        require(principal, Permission.REFUND_DECIDE)
        refund = await self._refunds.get_for_update(refund_id)
        if refund is None:
            raise NotFound
        if refund.status is not RefundStatus.PENDING_REVIEW:
            raise Conflict("This refund has already been decided.")
        now = self._clock()
        refund.reviewed_by_user_id = principal.user_id
        refund.reviewed_at = now
        refund.decision_note = redact_for_storage(note).text[:500] if note else None
        if not approve:
            refund.status = RefundStatus.REJECTED
        else:
            payment = await self._session.get(Payment, refund.payment_id, with_for_update=True)
            if payment is None:
                raise Conflict("The payment for this refund no longer exists.")
            prior = refunded_cents(await self._refunds.list_for_order(refund.order_id))
            if prior + refund.amount_cents > payment.amount_cents:
                raise Conflict("The refund would exceed the captured amount.")
            result = await self._gateway.refund(
                payment_reference=payment.provider_reference,
                amount_cents=refund.amount_cents,
                idempotency_key=f"refund:{refund.id}",
                metadata={"aegis_refund_number": refund.refund_number},
            )
            refund.provider_refund_id = result.provider_refund_id
            if result.status == SUCCEEDED:
                refund.status = RefundStatus.COMPLETED
                refund.completed_at = now
                settle_payment(payment, await self._refunds.list_for_order(refund.order_id))
            elif result.status == PENDING:
                refund.status = RefundStatus.PROCESSING  # finished by the provider's webhook
            else:
                refund.status = RefundStatus.FAILED
        try:
            await self._session.commit()
        except IntegrityError as exc:
            await self._session.rollback()
            raise Conflict("The refund could not be updated.") from exc
        await self._audit.record(
            "refund.decide",
            outcome=AuditOutcome.SUCCESS,
            actor=principal,
            resource_type="refund",
            resource_id=refund.id,
            details={
                "approved": approve,
                "status": refund.status.value,
                "amount_cents": refund.amount_cents,
            },
        )
        return refund

    async def apply_provider_update(
        self, *, provider_refund_id: str | None, refund_number: str | None, provider_status: str
    ) -> str:
        """Record the final outcome a payment provider reported for a processing refund.

        Idempotent: providers deliver events at least once and out of order, so only a refund
        that is still ``processing`` changes, and only to a final state. Returns what happened.
        """
        refund = await self._refunds.get_by_provider_reference_for_update(
            provider_refund_id=provider_refund_id, refund_number=refund_number
        )
        if refund is None:
            await self._session.rollback()
            return "unknown_refund"
        if provider_refund_id and refund.provider_refund_id is None:
            refund.provider_refund_id = provider_refund_id
        if refund.status is not RefundStatus.PROCESSING or provider_status == PENDING:
            await self._session.commit()
            return "unchanged"
        now = self._clock()
        if provider_status == SUCCEEDED:
            refund.status = RefundStatus.COMPLETED
            refund.completed_at = now
            payment = await self._session.get(Payment, refund.payment_id, with_for_update=True)
            if payment is not None:
                settle_payment(payment, await self._refunds.list_for_order(refund.order_id))
        else:
            refund.status = RefundStatus.FAILED
        await self._session.commit()
        await self._audit.record(
            "refund.provider_update",
            outcome=AuditOutcome.SUCCESS,
            actor_role="payment_provider",
            resource_type="refund",
            resource_id=refund.id,
            details={"status": refund.status.value},
        )
        return refund.status.value
