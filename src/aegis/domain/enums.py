"""Enumerations shared by the database, the API, the tools and the agent."""

from __future__ import annotations

from enum import StrEnum


class Role(StrEnum):
    CUSTOMER = "customer"
    SUPPORT_AGENT = "support_agent"
    SUPPORT_MANAGER = "support_manager"
    ADMIN = "admin"


STAFF_ROLES: frozenset[Role] = frozenset({Role.SUPPORT_AGENT, Role.SUPPORT_MANAGER, Role.ADMIN})


class CustomerTier(StrEnum):
    STANDARD = "standard"
    PLUS = "plus"
    VIP = "vip"


class StockStatus(StrEnum):
    IN_STOCK = "in_stock"
    LOW_STOCK = "low_stock"
    OUT_OF_STOCK = "out_of_stock"
    DISCONTINUED = "discontinued"


class OrderStatus(StrEnum):
    PENDING = "pending"
    PAID = "paid"
    PROCESSING = "processing"
    SHIPPED = "shipped"
    DELIVERED = "delivered"
    CANCELLED = "cancelled"
    RETURNED = "returned"


class PaymentStatus(StrEnum):
    PENDING = "pending"
    AUTHORIZED = "authorized"
    CAPTURED = "captured"
    FAILED = "failed"
    VOIDED = "voided"
    PARTIALLY_REFUNDED = "partially_refunded"
    REFUNDED = "refunded"


class PaymentMethod(StrEnum):
    CARD = "card"
    PAYPAL = "paypal"
    BANK_TRANSFER = "bank_transfer"
    GIFT_CARD = "gift_card"


class RefundStatus(StrEnum):
    PENDING_REVIEW = "pending_review"
    APPROVED = "approved"
    PROCESSING = "processing"
    COMPLETED = "completed"
    REJECTED = "rejected"
    FAILED = "failed"


OPEN_REFUND_STATUSES: frozenset[RefundStatus] = frozenset(
    {RefundStatus.PENDING_REVIEW, RefundStatus.APPROVED, RefundStatus.PROCESSING}
)


class RefundReason(StrEnum):
    DAMAGED = "damaged"
    DEFECTIVE = "defective"
    WRONG_ITEM = "wrong_item"
    NOT_AS_DESCRIBED = "not_as_described"
    NO_LONGER_NEEDED = "no_longer_needed"
    LATE_DELIVERY = "late_delivery"
    ORDER_CANCELLED = "order_cancelled"
    OTHER = "other"


class RequestSource(StrEnum):
    AI_AGENT = "ai_agent"
    CUSTOMER = "customer"
    STAFF = "staff"
    ESCALATION = "escalation"


class TicketStatus(StrEnum):
    OPEN = "open"
    IN_PROGRESS = "in_progress"
    PENDING_CUSTOMER = "pending_customer"
    RESOLVED = "resolved"
    CLOSED = "closed"


class Priority(StrEnum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    URGENT = "urgent"

    @property
    def rank(self) -> int:
        return _PRIORITY_RANK[self]

    @classmethod
    def highest(cls, *priorities: Priority) -> Priority:
        return max(priorities, key=lambda p: p.rank)


_PRIORITY_RANK = {Priority.LOW: 0, Priority.MEDIUM: 1, Priority.HIGH: 2, Priority.URGENT: 3}


class ConversationStatus(StrEnum):
    ACTIVE = "active"
    AWAITING_AGENT = "awaiting_agent"
    AGENT_ASSIGNED = "agent_assigned"
    RESOLVED = "resolved"
    CLOSED = "closed"


HUMAN_HANDLED_STATUSES: frozenset[ConversationStatus] = frozenset(
    {ConversationStatus.AWAITING_AGENT, ConversationStatus.AGENT_ASSIGNED}
)


class SenderType(StrEnum):
    CUSTOMER = "customer"
    ASSISTANT = "assistant"
    AGENT = "agent"
    SYSTEM = "system"


class KnowledgeVisibility(StrEnum):
    PUBLIC = "public"
    INTERNAL = "internal"


class KnowledgeCategory(StrEnum):
    FAQ = "faq"
    REFUND_POLICY = "refund_policy"
    SHIPPING_POLICY = "shipping_policy"
    CANCELLATION_POLICY = "cancellation_policy"
    WARRANTY = "warranty"
    PAYMENT_POLICY = "payment_policy"
    ACCOUNT_POLICY = "account_policy"
    PRIVACY_POLICY = "privacy_policy"
    PRODUCT_DOCS = "product_docs"
    INTERNAL_PLAYBOOK = "internal_playbook"


class DocumentStatus(StrEnum):
    PENDING = "pending"
    QUARANTINED = "quarantined"
    INDEXING = "indexing"
    INDEXED = "indexed"
    FAILED = "failed"
    ARCHIVED = "archived"


class ActionType(StrEnum):
    REFUND_REQUEST = "refund_request"
    ORDER_CANCELLATION = "order_cancellation"


class ActionStatus(StrEnum):
    PENDING = "pending"
    EXECUTING = "executing"
    EXECUTED = "executed"
    DECLINED = "declined"
    EXPIRED = "expired"
    FAILED = "failed"


class AuditOutcome(StrEnum):
    SUCCESS = "success"
    FAILURE = "failure"
    DENIED = "denied"
    ERROR = "error"


class HandoffReason(StrEnum):
    CUSTOMER_REQUEST = "customer_request"
    ACCOUNT_SECURITY = "account_security"
    PAYMENT_RISK = "payment_risk"
    LEGAL = "legal"
    LOW_CONFIDENCE = "low_confidence"
    REPEATED_FAILURE = "repeated_failure"
    UNSUPPORTED_REQUEST = "unsupported_request"
    SENSITIVE_DATA = "sensitive_data"
    NEGATIVE_SENTIMENT = "negative_sentiment"
    POLICY_EXCEPTION = "policy_exception"
    AI_UNAVAILABLE = "ai_unavailable"
    SUSPICIOUS_ACTIVITY = "suspicious_activity"


class Sentiment(StrEnum):
    POSITIVE = "positive"
    NEUTRAL = "neutral"
    NEGATIVE = "negative"
    VERY_NEGATIVE = "very_negative"
