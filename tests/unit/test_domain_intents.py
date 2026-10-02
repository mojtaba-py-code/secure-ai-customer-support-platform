from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest
from pydantic import BaseModel, Field

from aegis.agents.intents import IntentRegistry
from aegis.agents.rules import RuleBasedClassifier
from aegis.agents.signals import detect_signals
from aegis.domain.enums import OrderStatus, PaymentStatus, Priority, RefundStatus, Sentiment
from aegis.domain.identifiers import find_references
from aegis.domain.policies import (
    OrderFacts,
    PaymentFacts,
    RefundFacts,
    can_cancel_order,
    cancellation_blockers,
    evaluate_refund_eligibility,
)
from aegis.llm.schema import strict_json_schema
from aegis.repositories.common import clamp_page, escape_like
from aegis.tools.catalog import TOOLS

NOW = datetime(2026, 9, 30, 12, tzinfo=UTC)
TOOL_NAMES = frozenset(t.name for t in TOOLS)


def delivered(days_ago: int) -> OrderFacts:
    return OrderFacts(OrderStatus.DELIVERED, 10_000, NOW - timedelta(days=days_ago))


CAPTURED = PaymentFacts(PaymentStatus.CAPTURED, 10_000)


def test_refund_eligible_within_window() -> None:
    result = evaluate_refund_eligibility(delivered(5), CAPTURED, [], now=NOW)
    assert result.eligible
    assert result.max_refundable_cents == 10_000
    assert result.window_ends_at == NOW - timedelta(days=5) + timedelta(days=30)


@pytest.mark.parametrize(
    ("order", "payment", "refunds", "reason"),
    [
        (delivered(31), CAPTURED, [], "window_expired"),
        (OrderFacts(OrderStatus.SHIPPED, 10_000, None), CAPTURED, [], "not_delivered"),
        (OrderFacts(OrderStatus.CANCELLED, 10_000, None), CAPTURED, [], "order_cancelled"),
        (delivered(5), None, [], "no_captured_payment"),
        (delivered(5), PaymentFacts(PaymentStatus.FAILED, 10_000), [], "no_captured_payment"),
        (
            delivered(5),
            CAPTURED,
            [RefundFacts(RefundStatus.PENDING_REVIEW, 5_000)],
            "refund_in_progress",
        ),
        (delivered(5), CAPTURED, [RefundFacts(RefundStatus.COMPLETED, 10_000)], "fully_refunded"),
    ],
)
def test_refund_ineligible_cases(
    order: OrderFacts, payment: PaymentFacts | None, refunds: list[RefundFacts], reason: str
) -> None:
    result = evaluate_refund_eligibility(order, payment, refunds, now=NOW)
    assert not result.eligible
    assert reason in result.reasons
    assert result.max_refundable_cents == 0


def test_partial_refund_leaves_remainder() -> None:
    result = evaluate_refund_eligibility(
        delivered(3),
        PaymentFacts(PaymentStatus.PARTIALLY_REFUNDED, 10_000),
        [RefundFacts(RefundStatus.COMPLETED, 2_500), RefundFacts(RefundStatus.REJECTED, 7_500)],
        now=NOW,
    )
    assert result.eligible
    assert result.max_refundable_cents == 7_500


def test_cancellation_rules() -> None:
    assert can_cancel_order(OrderStatus.PROCESSING)
    assert not can_cancel_order(OrderStatus.SHIPPED)
    assert cancellation_blockers(OrderStatus.SHIPPED) == ("already_shipped",)
    assert cancellation_blockers(OrderStatus.CANCELLED) == ("already_cancelled",)
    assert cancellation_blockers(OrderStatus.RETURNED) == ("not_cancellable",)
    assert cancellation_blockers(OrderStatus.PAID) == ()


def test_reference_extraction() -> None:
    refs = find_references(
        "orders ord-100231 and ORD-100232, ticket TCK-40718263, refund RFD-100051, sku acm-sb500-01"
    )
    assert refs["order_number"] == ["ORD-100231", "ORD-100232"]
    assert refs["ticket_number"] == ["TCK-40718263"]
    assert refs["refund_number"] == ["RFD-100051"]
    assert refs["sku"] == ["ACM-SB500-01"]


def test_pagination_and_like_escaping() -> None:
    assert clamp_page(10_000, -5) == (100, 0)
    assert clamp_page(0, 50_000) == (1, 10_000)
    assert escape_like("100%_off\\") == "100\\%\\_off\\\\"


class Nested(BaseModel):
    title: str = Field(max_length=10, description="a field literally named title")


class Sample(BaseModel):
    order_number: str = Field(pattern=r"^ORD-\d+$", min_length=5)
    count: int = Field(ge=1, le=10)
    nested: Nested
    note: str | None = None


def test_strict_schema_for_provider_tool_use() -> None:
    schema = strict_json_schema(Sample)
    assert schema["additionalProperties"] is False
    assert schema["required"] == ["order_number", "count", "nested", "note"]
    assert "pattern" not in str(schema) and "minimum" not in str(schema) and "$defs" not in schema
    nested = schema["properties"]["nested"]
    assert nested["additionalProperties"] is False
    assert "title" in nested["properties"]


def test_registry_loads_and_adds_the_human_handoff_tool() -> None:
    registry = IntentRegistry.load_default(known_tools=TOOL_NAMES)
    assert "order_tracking" in registry.names
    assert all("request_human_agent" in intent.tools for intent in registry.all())
    assert registry.resolve("does-not-exist").name == "general_question"
    security = registry.get("security_problem")
    assert security is not None and security.always_escalate


@pytest.mark.parametrize(
    ("toml", "message"),
    [
        (
            (
                '[[intent]]\nname = "general_question"\ndescription = "anything else at all"\n'
                'default_priority = "low"\ntools = ["drop_database"]\n'
            ),
            "unknown tools",
        ),
        (
            '[[intent]]\nname = "order_tracking"\ndescription = "orders and stuff"\ndefault_priority = "low"\n',
            "fallback intent",
        ),
        (
            (
                '[[intent]]\nname = "general_question"\ndescription = "anything else at all"\n'
                'default_priority = "low"\n[[intent]]\nname = "general_question"\ndescription = "duplicate entry"\n'
                'default_priority = "low"\n'
            ),
            "duplicate",
        ),
    ],
)
def test_registry_validation(toml: str, message: str) -> None:
    with pytest.raises(ValueError, match=message):
        IntentRegistry.from_toml(toml, known_tools=TOOL_NAMES)


def test_signals() -> None:
    assert detect_signals("Can I talk to a real person please?").wants_human
    assert detect_signals("I will contact my lawyer about this").legal_threat
    assert detect_signals(
        "Someone logged in to my account, I did not make this purchase"
    ).account_compromise
    assert detect_signals("This is URGENT").urgent
    assert (
        detect_signals("This is terrible and unacceptable!!").sentiment is Sentiment.VERY_NEGATIVE
    )
    assert detect_signals("Thanks, that was helpful").sentiment is Sentiment.POSITIVE
    assert detect_signals("Where is ORD-100231?").order_numbers == ["ORD-100231"]


@pytest.mark.parametrize(
    ("text", "intent"),
    [
        ("Where is my order ORD-100232? It hasn't arrived", "order_tracking"),
        ("I want my money back for ORD-100231", "refund_request"),
        ("I was charged twice for my order", "payment_problem"),
        ("Please cancel order ORD-100233", "cancellation"),
        ("How much does express shipping cost?", "shipping_question"),
        ("Is the soundbar compatible with my TV?", "product_question"),
        ("I can't log in, reset my password", "account_problem"),
        ("My camera keeps disconnecting and shows an error", "technical_problem"),
        ("My account was hacked!", "security_problem"),
        ("This is the worst service, I want a manager", "complaint"),
        ("hello", "general_question"),
    ],
)
def test_rule_classifier(text: str, intent: str) -> None:
    registry = IntentRegistry.load_default(known_tools=TOOL_NAMES)
    result = RuleBasedClassifier(registry).classify(text, detect_signals(text))
    assert result.intent.name == intent


def test_rule_classifier_priority_and_human_flags() -> None:
    registry = IntentRegistry.load_default(known_tools=TOOL_NAMES)
    rules = RuleBasedClassifier(registry)
    urgent = rules.classify(
        "URGENT: where is my order ORD-100232",
        detect_signals("URGENT: where is my order ORD-100232"),
    )
    assert urgent.priority is Priority.HIGH
    human = rules.classify(
        "I want to speak to a human", detect_signals("I want to speak to a human")
    )
    assert human.requires_human
    assert rules.classify("hello", detect_signals("hello")).confidence < 0.5
