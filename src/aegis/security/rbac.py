"""Role-based access control.

Permissions are fine-grained and explicit; roles are fixed bundles of permissions. Two kinds of
check run on every protected operation:

1. **Capability** - does the role hold the permission at all? (``aegis.api.deps.require`` in
   the API layer, ``aegis.services.authz.require`` in services, the tool executor for
   model-initiated calls.)
2. **Ownership** - is this particular resource the caller's? Enforced inside the service and
   repository queries (``WHERE customer_id = :principal_customer``), so a missing check in a
   route cannot leak another customer's data. Resources that exist but belong to someone else
   are reported as *not found*, never *forbidden*, so identifiers cannot be enumerated.

Staff roles deliberately lack the customer-only permissions (creating a customer conversation,
confirming a customer's refund or cancellation): staff act through their own audited tools.
"""

from __future__ import annotations

from enum import StrEnum

from aegis.domain.enums import Role


class Permission(StrEnum):
    # customer self-service
    CONVERSATION_CREATE = "conversation:create"
    MESSAGE_SEND = "message:send"
    ACTION_CONFIRM_OWN = "action:confirm_own"
    CONVERSATION_READ_OWN = "conversation:read_own"
    ORDER_READ_OWN = "order:read_own"
    PAYMENT_READ_OWN = "payment:read_own"
    REFUND_READ_OWN = "refund:read_own"
    REFUND_REQUEST_OWN = "refund:request_own"
    ORDER_CANCEL_OWN = "order:cancel_own"
    TICKET_CREATE_OWN = "ticket:create_own"
    TICKET_READ_OWN = "ticket:read_own"
    PRODUCT_READ = "product:read"
    KB_READ_PUBLIC = "kb:read_public"
    ESCALATION_REQUEST = "escalation:request"
    PRIVACY_EXPORT_OWN = "privacy:export_own"
    # staff
    CONVERSATION_READ_ANY = "conversation:read_any"
    ORDER_READ_ANY = "order:read_any"
    PAYMENT_READ_ANY = "payment:read_any"
    REFUND_READ_ANY = "refund:read_any"
    TICKET_READ_ANY = "ticket:read_any"
    TICKET_UPDATE = "ticket:update"
    HANDOFF_QUEUE_READ = "handoff:queue_read"
    HANDOFF_CLAIM = "handoff:claim"
    HANDOFF_REPLY = "handoff:reply"
    HANDOFF_RESOLVE = "handoff:resolve"
    KB_READ_INTERNAL = "kb:read_internal"
    # managers
    HANDOFF_ASSIGN_ANY = "handoff:assign_any"
    REFUND_DECIDE = "refund:decide"
    USAGE_READ = "usage:read"
    # administrators
    KB_MANAGE = "kb:manage"
    USER_MANAGE = "user:manage"
    AUDIT_READ = "audit:read"
    PRIVACY_ERASE = "privacy:erase"


_CUSTOMER = frozenset(
    {
        Permission.CONVERSATION_CREATE,
        Permission.MESSAGE_SEND,
        Permission.ACTION_CONFIRM_OWN,
        Permission.CONVERSATION_READ_OWN,
        Permission.ORDER_READ_OWN,
        Permission.PAYMENT_READ_OWN,
        Permission.REFUND_READ_OWN,
        Permission.REFUND_REQUEST_OWN,
        Permission.ORDER_CANCEL_OWN,
        Permission.TICKET_CREATE_OWN,
        Permission.TICKET_READ_OWN,
        Permission.PRODUCT_READ,
        Permission.KB_READ_PUBLIC,
        Permission.ESCALATION_REQUEST,
        Permission.PRIVACY_EXPORT_OWN,
    }
)
_AGENT = frozenset(
    {
        Permission.PRODUCT_READ,
        Permission.KB_READ_PUBLIC,
        Permission.KB_READ_INTERNAL,
        Permission.CONVERSATION_READ_ANY,
        Permission.ORDER_READ_ANY,
        Permission.PAYMENT_READ_ANY,
        Permission.REFUND_READ_ANY,
        Permission.TICKET_READ_ANY,
        Permission.TICKET_UPDATE,
        Permission.HANDOFF_QUEUE_READ,
        Permission.HANDOFF_CLAIM,
        Permission.HANDOFF_REPLY,
        Permission.HANDOFF_RESOLVE,
    }
)
_MANAGER = _AGENT | {Permission.HANDOFF_ASSIGN_ANY, Permission.REFUND_DECIDE, Permission.USAGE_READ}
_ADMIN = _MANAGER | {
    Permission.KB_MANAGE,
    Permission.USER_MANAGE,
    Permission.AUDIT_READ,
    Permission.PRIVACY_ERASE,
}

ROLE_PERMISSIONS: dict[Role, frozenset[Permission]] = {
    Role.CUSTOMER: _CUSTOMER,
    Role.SUPPORT_AGENT: _AGENT,
    Role.SUPPORT_MANAGER: frozenset(_MANAGER),
    Role.ADMIN: frozenset(_ADMIN),
}


def has_permission(role: Role, permission: Permission) -> bool:
    return permission in ROLE_PERMISSIONS.get(role, frozenset())
