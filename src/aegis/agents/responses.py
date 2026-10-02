"""Fixed replies used when the model is not (or must not be) the author of the answer."""

from __future__ import annotations

from aegis.domain.enums import HandoffReason

CLARIFY = (
    "I want to make sure I help with the right thing. Could you tell me a little more - is this about an "
    "order (tracking or cancelling), a refund or payment, a product, or your account? If it is about an "
    "order, please include the order number (it looks like ORD-123456)."
)
UNAVAILABLE = (
    "I'm sorry - I'm having trouble completing your request right now. Please try again in a moment, "
    "or ask me to connect you with a support specialist."
)
CANNOT_HELP = (
    "I'm sorry, I can't help with that. I can help with orders, deliveries, refunds, payments, "
    "products and your account."
)
UNVERIFIED = (
    "I'm sorry - I couldn't verify all the details for that answer. Could you share the order number, "
    "or would you like me to connect you with a support specialist?"
)
HUMAN_HANDLING = "A support specialist is handling this conversation and will reply here."
SENSITIVE_DATA_WARNING = (
    "For your security, please don't share card numbers, security codes or passwords in chat - I've "
    "removed them from this conversation."
)

_HANDOFF = {
    HandoffReason.ACCOUNT_SECURITY: (
        "For your security I've passed this to our account-security team as an urgent case (ticket {ticket}). "
        "Please don't share passwords or card numbers here. If you think someone else can access your account, "
        "reset your password now with 'Forgot password' on the sign-in page."
    ),
    HandoffReason.LEGAL: (
        "I've passed your message to a senior member of our team (ticket {ticket}), who will follow up with you "
        "directly."
    ),
    HandoffReason.CUSTOMER_REQUEST: (
        "Of course - I've connected you with our support team (ticket {ticket}). A specialist will reply here "
        "as soon as possible."
    ),
    HandoffReason.SUSPICIOUS_ACTIVITY: (
        "I've passed this conversation to our support team (ticket {ticket}); a specialist will continue here."
    ),
}
_HANDOFF_DEFAULT = "I've passed this conversation to a support specialist (ticket {ticket}). They'll reply here as soon as possible."


def handoff_reply(reason: HandoffReason, ticket_number: str) -> str:
    return _HANDOFF.get(reason, _HANDOFF_DEFAULT).format(ticket=ticket_number)
