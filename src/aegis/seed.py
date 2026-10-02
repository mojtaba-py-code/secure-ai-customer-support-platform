"""Demo data: a fictional store ("Acme Home Electronics") with customers, orders in every
lifecycle state, payments, refunds, tickets and a knowledge base.

Rules:
* refused in production;
* idempotent (does nothing if users already exist);
* no hard-coded passwords: each demo account gets a random password, written once to a local,
  git-ignored file (``var/seed-credentials.json``) with owner-only permissions;
* all names, e-mail addresses (``example.com`` / ``acme.example``), phone numbers (555 range)
  and addresses are fictional.
"""

from __future__ import annotations

import json
import logging
import os
import secrets
import tomllib
from dataclasses import dataclass, field
from datetime import date, datetime, timedelta
from pathlib import Path
from typing import Any

from sqlalchemy import func, select

from aegis.bootstrap import AppContainer, RequestServices
from aegis.core.time import utc_now
from aegis.domain.enums import (
    CustomerTier,
    KnowledgeCategory,
    KnowledgeVisibility,
    OrderStatus,
    PaymentMethod,
    PaymentStatus,
    Priority,
    RefundReason,
    RefundStatus,
    RequestSource,
    Role,
    StockStatus,
    TicketStatus,
)
from aegis.models import Customer, Order, OrderItem, Payment, Product, Refund, SupportTicket, User

logger = logging.getLogger(__name__)

PRODUCTS: list[dict[str, Any]] = [
    {
        "sku": "ACM-SB500-01",
        "name": "Acme SoundBar 500",
        "category": "audio",
        "price": 29900,
        "warranty": 12,
        "description": "3.1-channel soundbar with HDMI eARC, Dolby Atmos virtualisation and Bluetooth 5.3.",
    },
    {
        "sku": "ACM-SW200-01",
        "name": "Acme Subwoofer 200",
        "category": "audio",
        "price": 19900,
        "warranty": 12,
        "description": "Wireless 8-inch subwoofer that pairs automatically with the SoundBar 500.",
    },
    {
        "sku": "ACM-HP700-01",
        "name": "Acme Wireless Headphones 700",
        "category": "audio",
        "price": 14900,
        "warranty": 12,
        "description": "Over-ear headphones with active noise cancelling and 40-hour battery life.",
    },
    {
        "sku": "ACM-EB100-02",
        "name": "Acme Earbuds 100",
        "category": "audio",
        "price": 7900,
        "warranty": 12,
        "description": "True wireless earbuds with IPX4 splash resistance and a pocket charging case.",
    },
    {
        "sku": "ACM-SC2-01",
        "name": "Acme SmartCam 2",
        "category": "smart home",
        "price": 8999,
        "warranty": 12,
        "description": "1080p indoor security camera with night vision and two-way audio; 2.4 GHz Wi-Fi.",
    },
    {
        "sku": "ACM-DB1-01",
        "name": "Acme Video Doorbell",
        "category": "smart home",
        "price": 12900,
        "warranty": 12,
        "description": "Battery video doorbell with motion alerts and a 160-degree field of view.",
    },
    {
        "sku": "ACM-RX3-01",
        "name": "Acme Mesh Router X3 (3-pack)",
        "category": "networking",
        "price": 24900,
        "warranty": 24,
        "description": "Wi-Fi 6 mesh system covering up to 5,500 square feet.",
    },
    {
        "sku": "ACM-RX1-01",
        "name": "Acme Router X1",
        "category": "networking",
        "price": 9900,
        "warranty": 12,
        "description": "Dual-band Wi-Fi 6 router for apartments and small homes.",
    },
    {
        "sku": "ACM-PB20-01",
        "name": "Acme PowerBank 20K",
        "category": "accessories",
        "price": 4900,
        "warranty": 12,
        "description": "20,000 mAh power bank with 45 W USB-C power delivery.",
        "stock": StockStatus.LOW_STOCK,
    },
    {
        "sku": "ACM-CH65-01",
        "name": "Acme 65W USB-C Charger",
        "category": "accessories",
        "price": 3900,
        "warranty": 12,
        "description": "Compact GaN charger with two USB-C ports and one USB-A port.",
    },
    {
        "sku": "ACM-TV55-01",
        "name": "Acme 55-inch 4K TV",
        "category": "tv",
        "price": 59900,
        "warranty": 24,
        "description": "55-inch 4K HDR television with built-in streaming apps and three HDMI 2.1 ports.",
    },
    {
        "sku": "ACM-GC50-01",
        "name": "Acme Gift Card $50",
        "category": "gift cards",
        "price": 5000,
        "warranty": 0,
        "description": "Digital gift card delivered by e-mail. Gift cards are not refundable.",
        "stock": StockStatus.IN_STOCK,
    },
]

CUSTOMERS: list[dict[str, Any]] = [
    {
        "number": "CUS-10001",
        "name": "Maya Thompson",
        "email": "maya.thompson@example.com",
        "tier": CustomerTier.VIP,
        "phone": "+1 555 0101 234",
        "address": "12 Harbor Lane, Springfield, IL 62701, USA",
    },
    {
        "number": "CUS-10002",
        "name": "Daniel Okafor",
        "email": "daniel.okafor@example.com",
        "tier": CustomerTier.STANDARD,
        "phone": "+1 555 0102 345",
        "address": "88 Pine Street, Madison, WI 53703, USA",
    },
    {
        "number": "CUS-10003",
        "name": "Sofia Rossi",
        "email": "sofia.rossi@example.com",
        "tier": CustomerTier.PLUS,
        "phone": "+1 555 0103 456",
        "address": "4 Elm Court, Burlington, VT 05401, USA",
    },
    {
        "number": "CUS-10004",
        "name": "Liam Chen",
        "email": "liam.chen@example.com",
        "tier": CustomerTier.STANDARD,
        "phone": "+1 555 0104 567",
        "address": "230 Oak Avenue, Boulder, CO 80302, USA",
    },
    {
        "number": "CUS-10005",
        "name": "Aisha Rahman",
        "email": "aisha.rahman@example.com",
        "tier": CustomerTier.PLUS,
        "phone": "+1 555 0105 678",
        "address": "7 Maple Road, Ann Arbor, MI 48104, USA",
    },
    {
        "number": "CUS-10006",
        "name": "Noah Williams",
        "email": "noah.williams@example.com",
        "tier": CustomerTier.STANDARD,
        "phone": "+1 555 0106 789",
        "address": "55 Cedar Blvd, Austin, TX 78701, USA",
    },
    {
        "number": "CUS-10007",
        "name": "Elena Petrova",
        "email": "elena.petrova@example.com",
        "tier": CustomerTier.STANDARD,
        "phone": "+1 555 0107 890",
        "address": "19 Birch Way, Portland, OR 97205, USA",
    },
    {
        "number": "CUS-10008",
        "name": "Mateo Garcia",
        "email": "mateo.garcia@example.com",
        "tier": CustomerTier.VIP,
        "phone": "+1 555 0108 901",
        "address": "301 Willow St, Tucson, AZ 85701, USA",
    },
    {
        "number": "CUS-10009",
        "name": "Hannah Mueller",
        "email": "hannah.mueller@example.com",
        "tier": CustomerTier.STANDARD,
        "phone": "+1 555 0109 012",
        "address": "66 Aspen Drive, Reno, NV 89501, USA",
    },
    {
        "number": "CUS-10010",
        "name": "Omar Haddad",
        "email": "omar.haddad@example.com",
        "tier": CustomerTier.STANDARD,
        "phone": "+1 555 0110 123",
        "address": "9 Spruce Place, Raleigh, NC 27601, USA",
    },
]

STAFF: list[dict[str, Any]] = [
    {"email": "sam.rivera@acme.example", "name": "Sam Rivera", "role": Role.SUPPORT_AGENT},
    {"email": "jordan.lee@acme.example", "name": "Jordan Lee", "role": Role.SUPPORT_AGENT},
    {"email": "priya.nair@acme.example", "name": "Priya Nair", "role": Role.SUPPORT_MANAGER},
    {"email": "alex.morgan@acme.example", "name": "Alex Morgan", "role": Role.ADMIN},
]


@dataclass(frozen=True, slots=True)
class OrderSpec:
    number: str
    customer: str
    status: OrderStatus
    items: list[tuple[str, int]]
    placed_days_ago: int
    shipped_days_ago: int | None = None
    delivered_days_ago: int | None = None
    payment: PaymentStatus = PaymentStatus.CAPTURED
    method: PaymentMethod = PaymentMethod.CARD
    failure_code: str | None = None
    carrier: str | None = None
    tracking: str | None = None
    eta_days_from_now: int | None = None


ORDERS: list[OrderSpec] = [
    # Maya: delivered recently (refund-eligible), in transit, still processing (cancellable)
    OrderSpec(
        "ORD-100231",
        "CUS-10001",
        OrderStatus.DELIVERED,
        [("ACM-SB500-01", 1), ("ACM-SW200-01", 1)],
        9,
        shipped_days_ago=7,
        delivered_days_ago=5,
        carrier="UPS",
        tracking="1Z84F3920311872641",
    ),
    OrderSpec(
        "ORD-100232",
        "CUS-10001",
        OrderStatus.SHIPPED,
        [("ACM-HP700-01", 1)],
        4,
        shipped_days_ago=2,
        carrier="DHL",
        tracking="JD014600006612345678",
        eta_days_from_now=2,
    ),
    OrderSpec(
        "ORD-100233",
        "CUS-10001",
        OrderStatus.PROCESSING,
        [("ACM-PB20-01", 2), ("ACM-CH65-01", 1)],
        1,
    ),
    # Daniel: refund window expired; failed payment
    OrderSpec(
        "ORD-100241",
        "CUS-10002",
        OrderStatus.DELIVERED,
        [("ACM-RX1-01", 1)],
        50,
        shipped_days_ago=48,
        delivered_days_ago=45,
        carrier="USPS",
        tracking="9400111899223197428490",
    ),
    OrderSpec(
        "ORD-100242",
        "CUS-10002",
        OrderStatus.PENDING,
        [("ACM-TV55-01", 1)],
        1,
        payment=PaymentStatus.FAILED,
        failure_code="card_declined",
    ),
    # Sofia: refund under review; cancelled order refunded
    OrderSpec(
        "ORD-100251",
        "CUS-10003",
        OrderStatus.DELIVERED,
        [("ACM-SC2-01", 2)],
        14,
        shipped_days_ago=12,
        delivered_days_ago=10,
        carrier="UPS",
        tracking="1Z84F3920311875521",
    ),
    OrderSpec(
        "ORD-100252",
        "CUS-10003",
        OrderStatus.CANCELLED,
        [("ACM-DB1-01", 1)],
        20,
        payment=PaymentStatus.REFUNDED,
    ),
    # Liam: awaiting payment; delivered via PayPal
    OrderSpec(
        "ORD-100261",
        "CUS-10004",
        OrderStatus.PENDING,
        [("ACM-EB100-02", 1)],
        0,
        payment=PaymentStatus.PENDING,
    ),
    OrderSpec(
        "ORD-100262",
        "CUS-10004",
        OrderStatus.DELIVERED,
        [("ACM-RX3-01", 1)],
        7,
        shipped_days_ago=5,
        delivered_days_ago=3,
        method=PaymentMethod.PAYPAL,
        carrier="DHL",
        tracking="JD014600006698765432",
    ),
    # Aisha: late shipment; partially refunded order
    OrderSpec(
        "ORD-100271",
        "CUS-10005",
        OrderStatus.SHIPPED,
        [("ACM-TV55-01", 1)],
        12,
        shipped_days_ago=10,
        carrier="UPS",
        tracking="1Z84F3920311879911",
        eta_days_from_now=-3,
    ),
    OrderSpec(
        "ORD-100272",
        "CUS-10005",
        OrderStatus.DELIVERED,
        [("ACM-HP700-01", 1), ("ACM-EB100-02", 1)],
        25,
        shipped_days_ago=23,
        delivered_days_ago=20,
        payment=PaymentStatus.PARTIALLY_REFUNDED,
        carrier="USPS",
        tracking="9400111899223197421234",
    ),
    # Noah: delivered yesterday; Elena: processing; Mateo: on the edge of the refund window
    OrderSpec(
        "ORD-100281",
        "CUS-10006",
        OrderStatus.DELIVERED,
        [("ACM-SC2-01", 1)],
        4,
        shipped_days_ago=3,
        delivered_days_ago=1,
        carrier="USPS",
        tracking="9400111899223197425555",
    ),
    OrderSpec(
        "ORD-100291", "CUS-10007", OrderStatus.PAID, [("ACM-RX1-01", 1), ("ACM-CH65-01", 1)], 0
    ),
    OrderSpec(
        "ORD-100301",
        "CUS-10008",
        OrderStatus.DELIVERED,
        [("ACM-SB500-01", 1)],
        33,
        shipped_days_ago=31,
        delivered_days_ago=29,
        carrier="UPS",
        tracking="1Z84F3920311870007",
    ),
    OrderSpec(
        "ORD-100311",
        "CUS-10009",
        OrderStatus.RETURNED,
        [("ACM-GC50-01", 1)],
        40,
        shipped_days_ago=40,
        delivered_days_ago=40,
        method=PaymentMethod.GIFT_CARD,
    ),
]


@dataclass(slots=True)
class SeedReport:
    created: bool
    credentials_file: str | None = None
    counts: dict[str, int] = field(default_factory=dict)


def _password() -> str:
    # Random, policy-compliant, never hard-coded.
    return f"{secrets.token_urlsafe(12)}-Aa1"


def _midday(days_ago: int, now: datetime) -> datetime:
    return (now - timedelta(days=days_ago)).replace(hour=14, minute=0, second=0, microsecond=0)


async def seed_demo_data(
    container: AppContainer,
    *,
    kb_dir: Path | None = None,
    credentials_path: Path = Path("var/seed-credentials.json"),
    now: datetime | None = None,
) -> SeedReport:
    if container.settings.is_production:
        msg = "refusing to seed demo data in production"
        raise RuntimeError(msg)
    now = now or utc_now()
    async with container.sessionmaker() as session:
        existing = (await session.execute(select(func.count()).select_from(User))).scalar_one()
        if existing:
            return SeedReport(created=False)

        credentials: dict[str, dict[str, str]] = {}
        products: dict[str, Product] = {}
        for spec in PRODUCTS:
            product = Product(
                sku=spec["sku"],
                name=spec["name"],
                category=spec["category"],
                description=spec["description"],
                price_cents=spec["price"],
                currency="USD",
                warranty_months=spec["warranty"],
                stock_status=spec.get("stock", StockStatus.IN_STOCK),
                is_active=True,
            )
            session.add(product)
            products[product.sku] = product

        customers: dict[str, Customer] = {}
        for index, spec in enumerate(CUSTOMERS):
            customer = Customer(
                customer_number=spec["number"],
                full_name=spec["name"],
                email=spec["email"],
                phone=spec["phone"],
                address=spec["address"],
                tier=spec["tier"],
                created_at=now - timedelta(days=400 - index * 17),
                updated_at=now,
            )
            session.add(customer)
            customers[customer.customer_number] = customer
        await session.flush()

        for spec in CUSTOMERS:
            password = _password()
            customer = customers[spec["number"]]
            session.add(
                User(
                    email=spec["email"],
                    password_hash=await container.hasher.hash_async(password),
                    role=Role.CUSTOMER,
                    display_name=spec["name"],
                    customer_id=customer.id,
                    password_changed_at=now,
                )
            )
            credentials[spec["email"]] = {
                "role": Role.CUSTOMER.value,
                "password": password,
                "name": spec["name"],
            }
        for spec in STAFF:
            password = _password()
            session.add(
                User(
                    email=spec["email"],
                    password_hash=await container.hasher.hash_async(password),
                    role=spec["role"],
                    display_name=spec["name"],
                    customer_id=None,
                    password_changed_at=now,
                )
            )
            credentials[spec["email"]] = {
                "role": spec["role"].value,
                "password": password,
                "name": spec["name"],
            }

        orders, payments = _build_orders(session, customers, products, now)
        await session.flush()
        _build_refunds_and_tickets(session, customers, orders, payments, now)
        await session.commit()

    counts = {
        "products": len(PRODUCTS),
        "customers": len(CUSTOMERS),
        "staff": len(STAFF),
        "orders": len(ORDERS),
    }
    if kb_dir is not None:
        counts["knowledge_documents"] = await seed_knowledge_base(container, kb_dir)
    written = _write_credentials(credentials_path, credentials)
    return SeedReport(created=True, credentials_file=str(written), counts=counts)


def _build_orders(
    session: Any, customers: dict[str, Customer], products: dict[str, Product], now: datetime
) -> tuple[dict[str, Order], dict[str, Payment]]:
    orders: dict[str, Order] = {}
    payments: dict[str, Payment] = {}
    for position, spec in enumerate(ORDERS):
        customer = customers[spec.customer]
        subtotal = sum(products[sku].price_cents * qty for sku, qty in spec.items)
        shipping = 0 if subtotal >= 5000 else 599
        placed = _midday(spec.placed_days_ago, now)
        order = Order(
            order_number=spec.number,
            customer_id=customer.id,
            status=spec.status,
            currency="USD",
            subtotal_cents=subtotal,
            shipping_cents=shipping,
            total_cents=subtotal + shipping,
            placed_at=placed,
            shipped_at=_midday(spec.shipped_days_ago, now)
            if spec.shipped_days_ago is not None
            else None,
            delivered_at=_midday(spec.delivered_days_ago, now)
            if spec.delivered_days_ago is not None
            else None,
            cancelled_at=placed + timedelta(hours=3)
            if spec.status is OrderStatus.CANCELLED
            else None,
            carrier=spec.carrier,
            tracking_number=spec.tracking,
            estimated_delivery=(now + timedelta(days=spec.eta_days_from_now)).date()
            if spec.eta_days_from_now is not None
            else None,
            shipping_address=customer.address,
            created_at=placed,
            updated_at=now,
        )
        for item_position, (sku, qty) in enumerate(spec.items, start=1):
            product = products[sku]
            order.items.append(
                OrderItem(
                    product_id=product.id,
                    position=item_position,
                    sku=sku,
                    product_name=product.name,
                    quantity=qty,
                    unit_price_cents=product.price_cents,
                )
            )
        session.add(order)
        captured = spec.payment in (
            PaymentStatus.CAPTURED,
            PaymentStatus.PARTIALLY_REFUNDED,
            PaymentStatus.REFUNDED,
        )
        payment = Payment(
            order=order,
            status=spec.payment,
            method=spec.method,
            amount_cents=subtotal + shipping,
            currency="USD",
            card_brand="Visa" if spec.method is PaymentMethod.CARD else None,
            card_last4=f"{4242 + position:04d}"[-4:] if spec.method is PaymentMethod.CARD else None,
            provider_reference=f"pi_demo_{spec.number.lower().replace('-', '')}",
            failure_code=spec.failure_code,
            created_at=placed,
            captured_at=placed + timedelta(hours=2) if captured else None,
        )
        session.add(payment)
        orders[spec.number] = order
        payments[spec.number] = payment
    return orders, payments


def _build_refunds_and_tickets(
    session: Any,
    customers: dict[str, Customer],
    orders: dict[str, Order],
    payments: dict[str, Payment],
    now: datetime,
) -> None:
    def payment_of(order: Order) -> Payment:
        return payments[order.order_number]

    sofia_review = orders["ORD-100251"]
    session.add(
        Refund(
            refund_number="RFD-100051",
            order_id=sofia_review.id,
            payment_id=payment_of(sofia_review).id,
            amount_cents=8999,
            currency="USD",
            status=RefundStatus.PENDING_REVIEW,
            reason=RefundReason.DEFECTIVE,
            customer_note="One of the two cameras will not connect to Wi-Fi.",
            source=RequestSource.CUSTOMER,
            created_at=now - timedelta(days=2),
            updated_at=now - timedelta(days=2),
        )
    )
    cancelled = orders["ORD-100252"]
    session.add(
        Refund(
            refund_number="RFD-100052",
            order_id=cancelled.id,
            payment_id=payment_of(cancelled).id,
            amount_cents=cancelled.total_cents,
            currency="USD",
            status=RefundStatus.COMPLETED,
            reason=RefundReason.ORDER_CANCELLED,
            source=RequestSource.CUSTOMER,
            completed_at=now - timedelta(days=19),
            created_at=now - timedelta(days=20),
            updated_at=now - timedelta(days=19),
        )
    )
    partial = orders["ORD-100272"]
    session.add(
        Refund(
            refund_number="RFD-100072",
            order_id=partial.id,
            payment_id=payment_of(partial).id,
            amount_cents=7900,
            currency="USD",
            status=RefundStatus.COMPLETED,
            reason=RefundReason.NO_LONGER_NEEDED,
            source=RequestSource.CUSTOMER,
            completed_at=now - timedelta(days=12),
            created_at=now - timedelta(days=15),
            updated_at=now - timedelta(days=12),
        )
    )
    session.add(
        SupportTicket(
            ticket_number="TCK-10000123",
            customer_id=customers["CUS-10003"].id,
            subject="SmartCam 2 will not connect",
            description="One of the two SmartCam 2 units from order ORD-100251 fails to join the Wi-Fi network.",
            category="technical_problem",
            priority=Priority.MEDIUM,
            status=TicketStatus.IN_PROGRESS,
            source=RequestSource.CUSTOMER,
            created_at=now - timedelta(days=3),
            updated_at=now - timedelta(days=2),
        )
    )
    session.add(
        SupportTicket(
            ticket_number="TCK-10000187",
            customer_id=customers["CUS-10005"].id,
            subject="TV delivery is late",
            description="Order ORD-100271 was expected earlier this week and has not arrived yet.",
            category="order_tracking",
            priority=Priority.HIGH,
            status=TicketStatus.OPEN,
            source=RequestSource.CUSTOMER,
            created_at=now - timedelta(days=1),
            updated_at=now - timedelta(days=1),
        )
    )


async def seed_knowledge_base(container: AppContainer, kb_dir: Path) -> int:
    manifest = tomllib.loads((kb_dir / "manifest.toml").read_text(encoding="utf-8"))
    created = 0
    for entry in manifest.get("document", []):
        path = kb_dir / str(entry["file"])
        async with container.sessionmaker() as session:
            services = RequestServices(container, session)
            effective = entry.get("effective_date")
            await services.knowledge.upload(
                None,
                filename=path.name,
                content_type="text/markdown",
                data=path.read_bytes(),
                title=str(entry["title"]),
                category=KnowledgeCategory(str(entry["category"])),
                visibility=KnowledgeVisibility(str(entry["visibility"])),
                slug=str(entry["slug"]),
                effective_date=date.fromisoformat(effective)
                if isinstance(effective, str)
                else None,
            )
            created += 1
    async with container.sessionmaker() as session:
        await RequestServices(container, session).knowledge.index_pending(limit=1_000)
    return created


def _write_credentials(path: Path, credentials: dict[str, dict[str, str]]) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = json.dumps(
        {
            "warning": "Demo credentials for local development only. Do not commit this file.",
            "accounts": credentials,
        },
        indent=2,
    )
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as handle:
        handle.write(payload)
    return path


__all__ = ["SeedReport", "seed_demo_data", "seed_knowledge_base"]
