"""ORM models. Importing this package registers every table on ``Base.metadata``."""

from aegis.models.commerce import Customer, Order, OrderItem, Payment, Product, Refund
from aegis.models.identity import (
    AuthSession,
    MfaChallenge,
    MfaRecoveryCode,
    PasswordResetToken,
    RefreshToken,
    User,
)
from aegis.models.knowledge import KnowledgeDocument
from aegis.models.operations import AuditEvent, IdempotencyRecord, LLMUsage
from aegis.models.support import Conversation, Message, PendingAction, SupportTicket

__all__ = [
    "AuditEvent",
    "AuthSession",
    "Conversation",
    "Customer",
    "IdempotencyRecord",
    "KnowledgeDocument",
    "LLMUsage",
    "Message",
    "MfaChallenge",
    "MfaRecoveryCode",
    "Order",
    "OrderItem",
    "PasswordResetToken",
    "Payment",
    "PendingAction",
    "Product",
    "RefreshToken",
    "Refund",
    "SupportTicket",
    "User",
]
