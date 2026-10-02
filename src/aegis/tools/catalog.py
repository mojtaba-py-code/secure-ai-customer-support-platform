"""The tool catalogue: schemas, descriptions and handlers.

Output design rule (data minimisation): tools return only what a support answer needs - order
status, dates, carrier, item names, masked payment info. Never the shipping address, e-mail,
phone number, full payment details or internal ids of other records.
"""

from __future__ import annotations

from datetime import date, datetime
from typing import Annotated, Literal

from pydantic import BaseModel, BeforeValidator, Field, StringConstraints

from aegis.core.errors import NotFound, ValidationFailed
from aegis.domain.enums import HandoffReason, RefundReason, RequestSource
from aegis.domain.identifiers import ORDER_NUMBER_PATTERN, SKU_PATTERN, TICKET_NUMBER_PATTERN
from aegis.security.rbac import Permission
from aegis.security.redaction import redact_for_storage
from aegis.security.text import normalize_text, truncate
from aegis.services.commerce import latest_payment, refunded_cents
from aegis.tools.base import (
    EscalationRequest,
    ProposedAction,
    SideEffect,
    StrictModel,
    ToolContext,
    ToolDefinition,
    ToolFailure,
)


def _upper(value: object) -> object:
    return value.strip().upper() if isinstance(value, str) else value


OrderNumber = Annotated[
    str, BeforeValidator(_upper), StringConstraints(pattern=ORDER_NUMBER_PATTERN, max_length=16)
]
TicketNumber = Annotated[
    str, BeforeValidator(_upper), StringConstraints(pattern=TICKET_NUMBER_PATTERN, max_length=16)
]
Sku = Annotated[str, BeforeValidator(_upper), StringConstraints(pattern=SKU_PATTERN, max_length=32)]


def money(cents: int, currency: str) -> str:
    return f"{cents / 100:.2f} {currency}"


def day(value: datetime | date | None) -> str | None:
    if value is None:
        return None
    return value.date().isoformat() if isinstance(value, datetime) else value.isoformat()


ELIGIBILITY_REASONS = {
    "not_delivered": "The order has not been delivered yet.",
    "window_expired": "The 30-day refund window for this order has ended.",
    "order_cancelled": "The order was cancelled; cancelled orders are refunded automatically.",
    "no_captured_payment": "There is no completed payment on this order to refund.",
    "refund_in_progress": "A refund for this order is already in progress.",
    "fully_refunded": "This order has already been fully refunded.",
}
CANCELLATION_REASONS = {
    "already_shipped": "The order has already shipped; it can be returned after delivery instead.",
    "already_cancelled": "The order is already cancelled.",
    "not_cancellable": "The order can no longer be cancelled.",
}
PAYMENT_FAILURES = {
    "card_declined": "The card issuer declined the payment.",
    "insufficient_funds": "The card issuer reported insufficient funds.",
    "expired_card": "The card on file has expired.",
    "authentication_required": "The bank required extra authentication (3-D Secure) that was not completed.",
    "processing_error": "The payment processor reported a temporary error.",
}


# --- inputs ------------------------------------------------------------------------------------------
class OrderInput(StrictModel):
    order_number: OrderNumber = Field(description="The order reference, e.g. ORD-100234.")


class RecentOrdersInput(StrictModel):
    limit: int = Field(ge=1, le=10, description="How many recent orders to list (1-10).")


class RefundRequestInput(StrictModel):
    order_number: OrderNumber = Field(description="The order reference, e.g. ORD-100234.")
    reason: RefundReason = Field(description="Why the customer wants a refund.")
    note: Annotated[str, StringConstraints(max_length=500)] | None = Field(
        description="Optional short note in the customer's words, or null."
    )


class TicketCreateInput(StrictModel):
    subject: Annotated[str, StringConstraints(min_length=3, max_length=150)] = Field(
        description="A short summary of the issue."
    )
    description: Annotated[str, StringConstraints(min_length=10, max_length=2000)] = Field(
        description="What happened and what the customer needs, without card numbers or passwords."
    )


class TicketInput(StrictModel):
    ticket_number: TicketNumber = Field(description="The ticket reference, e.g. TCK-40718263.")


class ProductInput(StrictModel):
    sku: Sku | None = Field(
        description="Exact product SKU if known (e.g. ACM-SB500-01), else null."
    )
    query: Annotated[str, StringConstraints(max_length=80)] | None = Field(
        description="Product name or keywords when the SKU is unknown, else null."
    )


class EmptyInput(StrictModel):
    pass


HumanReason = Literal[
    "customer_request",
    "account_security",
    "payment_risk",
    "legal",
    "unsupported_request",
    "policy_exception",
    "sensitive_data",
    "negative_sentiment",
]


class HandoffInput(StrictModel):
    reason: HumanReason = Field(description="Why a human needs to take over.")
    summary: Annotated[str, StringConstraints(min_length=5, max_length=500)] = Field(
        description="One or two sentences for the human agent summarising the issue."
    )


# --- outputs -----------------------------------------------------------------------------------------
class ItemBrief(BaseModel):
    name: str
    sku: str
    quantity: int


class OrderStatusOutput(BaseModel):
    order_number: str
    status: str
    placed_on: str | None
    shipped_on: str | None
    delivered_on: str | None
    estimated_delivery: str | None
    carrier: str | None
    tracking_number: str | None
    items: list[ItemBrief]


class OrderBrief(BaseModel):
    order_number: str
    placed_on: str | None
    status: str
    total: str


class RecentOrdersOutput(BaseModel):
    orders: list[OrderBrief]


class ItemDetail(BaseModel):
    name: str
    sku: str
    quantity: int
    unit_price: str


class PaymentBrief(BaseModel):
    status: str
    method: str
    card: str | None
    amount: str


class OrderDetailsOutput(BaseModel):
    order_number: str
    status: str
    placed_on: str | None
    items: list[ItemDetail]
    subtotal: str
    shipping: str
    total: str
    payment: PaymentBrief | None


class PaymentStatusOutput(BaseModel):
    order_number: str
    payment_status: str | None
    method: str | None
    amount: str | None
    captured_on: str | None
    failure_reason: str | None
    refunded_total: str


class EligibilityOutput(BaseModel):
    order_number: str
    eligible: bool
    reasons: list[str]
    max_refundable: str | None
    refund_window_ends_on: str | None


class RefundBrief(BaseModel):
    refund_number: str
    amount: str
    status: str
    requested_on: str | None
    completed_on: str | None


class RefundStatusOutput(BaseModel):
    order_number: str
    refunds: list[RefundBrief]


class ProposedActionOutput(BaseModel):
    action_id: str
    action: str
    summary: str
    requires_customer_confirmation: bool
    expires_at: str
    instructions: str


class TicketOutput(BaseModel):
    ticket_number: str
    subject: str
    status: str
    priority: str
    created_on: str | None


class ProductBrief(BaseModel):
    sku: str
    name: str
    category: str
    price: str
    warranty_months: int
    availability: str
    description: str


class ProductOutput(BaseModel):
    products: list[ProductBrief]


class ProfileOutput(BaseModel):
    first_name: str
    tier: str
    member_since: str | None
    order_count: int


class HandoffOutput(BaseModel):
    status: str
    message: str


# --- handlers ----------------------------------------------------------------------------------------
async def get_order_status(ctx: ToolContext, args: OrderInput) -> OrderStatusOutput:
    order = await ctx.services.orders.get_order(ctx.principal, args.order_number)
    return OrderStatusOutput(
        order_number=order.order_number,
        status=order.status.value,
        placed_on=day(order.placed_at),
        shipped_on=day(order.shipped_at),
        delivered_on=day(order.delivered_at),
        estimated_delivery=day(order.estimated_delivery),
        carrier=order.carrier,
        tracking_number=order.tracking_number,
        items=[ItemBrief(name=i.product_name, sku=i.sku, quantity=i.quantity) for i in order.items],
    )


async def list_recent_orders(ctx: ToolContext, args: RecentOrdersInput) -> RecentOrdersOutput:
    orders = await ctx.services.orders.list_orders(ctx.principal, limit=args.limit, offset=0)
    return RecentOrdersOutput(
        orders=[
            OrderBrief(
                order_number=o.order_number,
                placed_on=day(o.placed_at),
                status=o.status.value,
                total=money(o.total_cents, o.currency),
            )
            for o in orders
        ]
    )


async def get_order_details(ctx: ToolContext, args: OrderInput) -> OrderDetailsOutput:
    order = await ctx.services.orders.get_order(ctx.principal, args.order_number)
    payment = latest_payment(order)
    return OrderDetailsOutput(
        order_number=order.order_number,
        status=order.status.value,
        placed_on=day(order.placed_at),
        items=[
            ItemDetail(
                name=i.product_name,
                sku=i.sku,
                quantity=i.quantity,
                unit_price=money(i.unit_price_cents, order.currency),
            )
            for i in order.items
        ],
        subtotal=money(order.subtotal_cents, order.currency),
        shipping=money(order.shipping_cents, order.currency),
        total=money(order.total_cents, order.currency),
        payment=PaymentBrief(
            status=payment.status.value,
            method=payment.method.value,
            card=f"{payment.card_brand} ending {payment.card_last4}"
            if payment.card_last4
            else None,
            amount=money(payment.amount_cents, payment.currency),
        )
        if payment
        else None,
    )


async def check_payment_status(ctx: ToolContext, args: OrderInput) -> PaymentStatusOutput:
    order, payment = await ctx.services.orders.payment_status(ctx.principal, args.order_number)
    _, refunds = await ctx.services.orders.refunds_for_order(ctx.principal, args.order_number)
    return PaymentStatusOutput(
        order_number=order.order_number,
        payment_status=payment.status.value if payment else None,
        method=payment.method.value if payment else None,
        amount=money(payment.amount_cents, payment.currency) if payment else None,
        captured_on=day(payment.captured_at) if payment else None,
        failure_reason=PAYMENT_FAILURES.get(
            payment.failure_code or "", "The payment was not completed."
        )
        if payment and payment.failure_code
        else None,
        refunded_total=money(refunded_cents(refunds), order.currency),
    )


async def check_refund_eligibility(ctx: ToolContext, args: OrderInput) -> EligibilityOutput:
    order, eligibility = await ctx.services.orders.refund_eligibility(
        ctx.principal, args.order_number
    )
    return EligibilityOutput(
        order_number=order.order_number,
        eligible=eligibility.eligible,
        reasons=[ELIGIBILITY_REASONS.get(r, r) for r in eligibility.reasons],
        max_refundable=money(eligibility.max_refundable_cents, order.currency)
        if eligibility.eligible
        else None,
        refund_window_ends_on=day(eligibility.window_ends_at),
    )


async def get_refund_status(ctx: ToolContext, args: OrderInput) -> RefundStatusOutput:
    order, refunds = await ctx.services.orders.refunds_for_order(ctx.principal, args.order_number)
    return RefundStatusOutput(
        order_number=order.order_number,
        refunds=[
            RefundBrief(
                refund_number=r.refund_number,
                amount=money(r.amount_cents, r.currency),
                status=r.status.value,
                requested_on=day(r.created_at),
                completed_on=day(r.completed_at),
            )
            for r in refunds
        ],
    )


def _proposal_output(
    ctx: ToolContext, action_id: str, action_type: str, summary: str, expires: datetime
) -> ProposedActionOutput:
    ctx.state.proposed_actions.append(
        ProposedAction(
            action_id=action_id,
            action_type=action_type,
            summary=summary,
            expires_at=expires.isoformat(),
        )
    )
    return ProposedActionOutput(
        action_id=action_id,
        action=action_type,
        summary=summary,
        requires_customer_confirmation=True,
        expires_at=expires.isoformat(timespec="minutes"),
        instructions="Nothing has changed yet. Ask the customer to review and press Confirm in the app.",
    )


async def request_refund(ctx: ToolContext, args: RefundRequestInput) -> ProposedActionOutput:
    try:
        action = await ctx.services.actions.propose_refund(
            ctx.principal,
            conversation_id=ctx.conversation_id,
            order_number=args.order_number,
            reason=args.reason,
            note=args.note,
        )
    except ValidationFailed as exc:
        reasons = [ELIGIBILITY_REASONS.get(r, r) for r in exc.details.get("reasons", [])]
        raise ToolFailure("not_eligible", " ".join(reasons) or exc.public_message) from exc
    return _proposal_output(
        ctx, str(action.id), action.action_type.value, action.summary, action.expires_at
    )


async def cancel_order(ctx: ToolContext, args: OrderInput) -> ProposedActionOutput:
    try:
        action = await ctx.services.actions.propose_cancellation(
            ctx.principal, conversation_id=ctx.conversation_id, order_number=args.order_number
        )
    except ValidationFailed as exc:
        reasons = [CANCELLATION_REASONS.get(r, r) for r in exc.details.get("reasons", [])]
        raise ToolFailure("not_cancellable", " ".join(reasons) or exc.public_message) from exc
    return _proposal_output(
        ctx, str(action.id), action.action_type.value, action.summary, action.expires_at
    )


async def create_support_ticket(ctx: ToolContext, args: TicketCreateInput) -> TicketOutput:
    ticket = await ctx.services.tickets.create(
        ctx.principal,
        subject=args.subject,
        description=args.description,
        category=ctx.intent,
        priority=ctx.priority,  # decided by policy, not by the model
        source=RequestSource.AI_AGENT,
        conversation_id=ctx.conversation_id,
        idempotency_key=f"agent-ticket:{ctx.message_id}",
    )
    ctx.state.tickets_created.append(ticket.ticket_number)
    return TicketOutput(
        ticket_number=ticket.ticket_number,
        subject=ticket.subject,
        status=ticket.status.value,
        priority=ticket.priority.value,
        created_on=day(ticket.created_at),
    )


async def get_ticket_status(ctx: ToolContext, args: TicketInput) -> TicketOutput:
    ticket = await ctx.services.tickets.get_by_number(ctx.principal, args.ticket_number)
    return TicketOutput(
        ticket_number=ticket.ticket_number,
        subject=ticket.subject,
        status=ticket.status.value,
        priority=ticket.priority.value,
        created_on=day(ticket.created_at),
    )


async def get_product_information(ctx: ToolContext, args: ProductInput) -> ProductOutput:
    if not args.sku and not args.query:
        raise ToolFailure("invalid_arguments", "Provide a SKU or a product name.")
    products = await ctx.services.products.lookup(ctx.principal, sku=args.sku, query=args.query)
    if not products:
        raise NotFound("No matching product was found in the catalogue.")
    return ProductOutput(
        products=[
            ProductBrief(
                sku=p.sku,
                name=p.name,
                category=p.category,
                price=money(p.price_cents, p.currency),
                warranty_months=p.warranty_months,
                availability=p.stock_status.value.replace("_", " "),
                description=truncate(p.description, 400),
            )
            for p in products
        ]
    )


async def get_customer_profile(ctx: ToolContext, args: EmptyInput) -> ProfileOutput:
    summary = await ctx.services.customers.summary(ctx.principal)
    return ProfileOutput(
        first_name=summary.first_name,
        tier=summary.tier,
        member_since=day(summary.member_since),
        order_count=summary.order_count,
    )


async def request_human_agent(ctx: ToolContext, args: HandoffInput) -> HandoffOutput:
    if ctx.state.escalation is None:
        ctx.state.escalation = EscalationRequest(
            reason=HandoffReason(args.reason),
            summary=truncate(redact_for_storage(normalize_text(args.summary)).text, 500),
        )
    return HandoffOutput(
        status="handoff_requested",
        message="A human support specialist will take over this conversation.",
    )


TOOLS: tuple[ToolDefinition, ...] = (
    ToolDefinition(
        name="get_order_status",
        description=(
            "Look up the shipping status of ONE of the signed-in customer's orders: status, ship/delivery dates, "
            "carrier, tracking number and items. Call this whenever the customer asks where an order is or when it "
            "will arrive and gives an order number."
        ),
        input_model=OrderInput,
        handler=get_order_status,
        permission=Permission.ORDER_READ_OWN,
        side_effect=SideEffect.READ,
    ),
    ToolDefinition(
        name="list_recent_orders",
        description=(
            "List the signed-in customer's most recent orders (number, date, status, total). Call this when the "
            "customer refers to an order without giving its number."
        ),
        input_model=RecentOrdersInput,
        handler=list_recent_orders,
        permission=Permission.ORDER_READ_OWN,
        side_effect=SideEffect.READ,
        max_calls_per_turn=1,
    ),
    ToolDefinition(
        name="get_order_details",
        description=(
            "Get the items, prices, totals and masked payment summary of one of the customer's orders. Call this "
            "for questions about what was ordered or what it cost."
        ),
        input_model=OrderInput,
        handler=get_order_details,
        permission=Permission.ORDER_READ_OWN,
        side_effect=SideEffect.READ,
    ),
    ToolDefinition(
        name="check_payment_status",
        description=(
            "Check the payment state of one of the customer's orders (captured, failed, refunded) and any refunded "
            "total. Call this for charge, billing or failed-payment questions."
        ),
        input_model=OrderInput,
        handler=check_payment_status,
        permission=Permission.PAYMENT_READ_OWN,
        side_effect=SideEffect.READ,
    ),
    ToolDefinition(
        name="check_refund_eligibility",
        description=(
            "Apply the store's refund policy to one of the customer's orders and return whether it is eligible, "
            "why not, and the maximum refundable amount. Always call this before discussing a refund amount."
        ),
        input_model=OrderInput,
        handler=check_refund_eligibility,
        permission=Permission.REFUND_READ_OWN,
        side_effect=SideEffect.READ,
    ),
    ToolDefinition(
        name="get_refund_status",
        description="List refunds on one of the customer's orders with their status. Call this for 'where is my refund'.",
        input_model=OrderInput,
        handler=get_refund_status,
        permission=Permission.REFUND_READ_OWN,
        side_effect=SideEffect.READ,
    ),
    ToolDefinition(
        name="request_refund",
        description=(
            "Prepare a refund request for an eligible order. This does NOT refund anything: it creates a request "
            "the customer must confirm in the app, which staff then review. Call it only when the customer "
            "explicitly asks for a refund."
        ),
        input_model=RefundRequestInput,
        handler=request_refund,
        permission=Permission.REFUND_REQUEST_OWN,
        side_effect=SideEffect.PROPOSE,
        max_calls_per_turn=1,
    ),
    ToolDefinition(
        name="cancel_order",
        description=(
            "Prepare the cancellation of an order that has not shipped. Nothing changes until the customer "
            "confirms in the app. Call it only when the customer explicitly asks to cancel."
        ),
        input_model=OrderInput,
        handler=cancel_order,
        permission=Permission.ORDER_CANCEL_OWN,
        side_effect=SideEffect.PROPOSE,
        max_calls_per_turn=1,
    ),
    ToolDefinition(
        name="create_support_ticket",
        description=(
            "Open a support ticket for an issue that needs follow-up by the support team (e.g. a technical fault "
            "you cannot resolve). Do not use it for questions you can answer."
        ),
        input_model=TicketCreateInput,
        handler=create_support_ticket,
        permission=Permission.TICKET_CREATE_OWN,
        side_effect=SideEffect.WRITE,
        max_calls_per_turn=1,
    ),
    ToolDefinition(
        name="get_ticket_status",
        description="Look up one of the customer's support tickets by its reference number.",
        input_model=TicketInput,
        handler=get_ticket_status,
        permission=Permission.TICKET_READ_OWN,
        side_effect=SideEffect.READ,
    ),
    ToolDefinition(
        name="get_product_information",
        description=(
            "Look up products in the public catalogue by SKU or name: price, warranty, availability and a short "
            "description. Call this for product questions."
        ),
        input_model=ProductInput,
        handler=get_product_information,
        permission=Permission.PRODUCT_READ,
        side_effect=SideEffect.READ,
    ),
    ToolDefinition(
        name="get_customer_profile",
        description="Get the signed-in customer's first name, membership tier and number of orders.",
        input_model=EmptyInput,
        handler=get_customer_profile,
        permission=Permission.ORDER_READ_OWN,
        side_effect=SideEffect.READ,
        max_calls_per_turn=1,
    ),
    ToolDefinition(
        name="request_human_agent",
        description=(
            "Hand the conversation to a human support specialist. Call this when the customer asks for a human, "
            "reports a hacked account or unauthorised charges, mentions legal action, needs an exception to "
            "policy, or when you cannot help."
        ),
        input_model=HandoffInput,
        handler=request_human_agent,
        permission=Permission.ESCALATION_REQUEST,
        side_effect=SideEffect.ESCALATE,
        max_calls_per_turn=1,
    ),
)
