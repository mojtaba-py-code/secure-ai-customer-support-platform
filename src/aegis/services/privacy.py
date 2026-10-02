"""Data-subject requests: access (export), erasure and the retention period.

* **Export** - a customer downloads everything the platform holds about them: profile, login,
  orders with payments and refunds, conversations and tickets. Internal metadata (classifier
  output, guard findings, staff-only notes) is not included.
* **Erasure** - an administrator anonymises a customer on request (usually after a verified
  ``/privacy/erasure-request`` ticket). Contact data, all free text (messages, summaries, tickets,
  notes) and the login are erased irreversibly; sessions and second factors are removed. Orders,
  payments and refunds stay - accounting law requires them - but no longer lead to a person.
  Erasure waits until no order, refund or confirmed action is still in progress, and the
  customer number must be typed as confirmation.
* **Retention** - the worker erases the text of conversations that finished more than
  ``AEGIS_CONVERSATION_RETENTION_DAYS`` ago.

Every request is audited, with counts but never the data itself.
"""

from __future__ import annotations

import secrets
import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta

from sqlalchemy.ext.asyncio import AsyncSession

from aegis.core.errors import Conflict, NotFound, PermissionDenied, ValidationFailed
from aegis.core.time import Clock, utc_now
from aegis.domain.enums import AuditOutcome, Priority, RequestSource, SenderType
from aegis.models import SupportTicket
from aegis.repositories.identity import AuthSessionRepository, MfaRepository
from aegis.repositories.privacy import PrivacyRepository
from aegis.schemas.privacy import (
    ExportAccount,
    ExportConversation,
    ExportCustomer,
    ExportMessage,
    ExportOrder,
    ExportOrderItem,
    ExportPayment,
    ExportRefund,
    ExportTicket,
    PrivacyExport,
)
from aegis.security.passwords import PasswordHasher
from aegis.security.principal import Principal
from aegis.security.rbac import Permission
from aegis.services.audit import AuditService
from aegis.services.authz import require
from aegis.services.mfa import clear_second_factor
from aegis.services.tickets import TicketService

ERASED_TEXT = "[erased]"
EXPIRED_TEXT = "[removed after the retention period]"
ERASED_NAME = "Erased customer"
EXPORTED_SENDERS = frozenset({SenderType.CUSTOMER, SenderType.ASSISTANT, SenderType.AGENT})


@dataclass(frozen=True, slots=True)
class ErasureReport:
    customer_id: uuid.UUID
    erased_at: datetime
    counts: dict[str, int]


def erased_address(record_id: uuid.UUID) -> str:
    """A unique, undeliverable placeholder address (``.invalid`` is reserved, RFC 2606)."""
    return f"erased-{record_id.hex}@erased.invalid"


class PrivacyService:
    def __init__(
        self,
        session: AsyncSession,
        *,
        hasher: PasswordHasher,
        tickets: TicketService,
        audit: AuditService,
        clock: Clock = utc_now,
    ) -> None:
        self._session = session
        self._repo = PrivacyRepository(session)
        self._sessions = AuthSessionRepository(session)
        self._mfa = MfaRepository(session)
        self._hasher = hasher
        self._tickets = tickets
        self._audit = audit
        self._clock = clock

    # --- access ------------------------------------------------------------------------------------
    async def export(self, principal: Principal) -> PrivacyExport:
        require(principal, Permission.PRIVACY_EXPORT_OWN)
        if principal.customer_id is None:
            raise PermissionDenied
        customer = await self._repo.customer(principal.customer_id)
        if customer is None:
            raise NotFound
        orders = await self._repo.orders(customer.id)
        numbers = {order.id: order.order_number for order in orders}
        conversations = await self._repo.conversations(customer.id)
        messages = await self._repo.messages([c.id for c in conversations])
        by_conversation: dict[uuid.UUID, list[ExportMessage]] = {}
        for message in messages:
            if message.sender_type in EXPORTED_SENDERS:
                by_conversation.setdefault(message.conversation_id, []).append(
                    ExportMessage(
                        sender_type=message.sender_type,
                        content=message.content,
                        created_at=message.created_at,
                    )
                )
        export = PrivacyExport(
            generated_at=self._clock(),
            customer=ExportCustomer.model_validate(customer),
            accounts=[
                ExportAccount(
                    email=user.email,
                    display_name=user.display_name,
                    role=user.role,
                    created_at=user.created_at,
                    last_login_at=user.last_login_at,
                    two_factor_enabled=user.mfa_enabled_at is not None,
                )
                for user in await self._repo.users(customer.id)
            ],
            orders=[
                ExportOrder(
                    order_number=order.order_number,
                    status=order.status,
                    placed_at=order.placed_at,
                    currency=order.currency,
                    subtotal_cents=order.subtotal_cents,
                    shipping_cents=order.shipping_cents,
                    total_cents=order.total_cents,
                    shipping_address=order.shipping_address,
                    carrier=order.carrier,
                    tracking_number=order.tracking_number,
                    items=[ExportOrderItem.model_validate(item) for item in order.items],
                    payments=[ExportPayment.model_validate(p) for p in order.payments],
                )
                for order in orders
            ],
            refunds=[
                ExportRefund(
                    refund_number=refund.refund_number,
                    order_number=numbers.get(refund.order_id, ""),
                    status=refund.status,
                    amount_cents=refund.amount_cents,
                    currency=refund.currency,
                    reason=refund.reason,
                    customer_note=refund.customer_note,
                    created_at=refund.created_at,
                    completed_at=refund.completed_at,
                )
                for refund in await self._repo.refunds(customer.id)
            ],
            conversations=[
                ExportConversation(
                    id=conversation.id,
                    subject=conversation.subject,
                    status=conversation.status,
                    created_at=conversation.created_at,
                    messages=by_conversation.get(conversation.id, []),
                )
                for conversation in conversations
            ],
            tickets=[
                ExportTicket.model_validate(ticket)
                for ticket in await self._repo.tickets(customer.id)
            ],
        )
        await self._audit.record(
            "privacy.export",
            outcome=AuditOutcome.SUCCESS,
            actor=principal,
            resource_type="customer",
            resource_id=customer.id,
            details={
                "orders": len(export.orders),
                "conversations": len(export.conversations),
                "tickets": len(export.tickets),
            },
        )
        return export

    # --- erasure -----------------------------------------------------------------------------------
    async def request_erasure(self, principal: Principal) -> SupportTicket:
        """Open (or return today's) ticket asking the privacy team to erase the customer's data."""
        if principal.customer_id is None:
            raise PermissionDenied
        today = self._clock().date().isoformat()
        ticket = await self._tickets.create(
            principal,
            subject="Request to erase my personal data",
            description=(
                "The customer asked for their personal data to be erased. Verify the request, "
                "then an administrator runs the erasure for this customer."
            ),
            category="privacy",
            priority=Priority.MEDIUM,
            source=RequestSource.CUSTOMER,
            idempotency_key=f"privacy-erasure-{principal.customer_id.hex}-{today}",
        )
        await self._audit.record(
            "privacy.erasure_request",
            outcome=AuditOutcome.SUCCESS,
            actor=principal,
            resource_type="ticket",
            resource_id=ticket.id,
        )
        return ticket

    async def erase(
        self, principal: Principal, customer_id: uuid.UUID, *, confirmation: str
    ) -> ErasureReport:
        require(principal, Permission.PRIVACY_ERASE)
        customer = await self._repo.customer(customer_id, for_update=True)
        if customer is None:
            raise NotFound
        if customer.erased_at is not None:
            raise Conflict("This customer's personal data has already been erased.")
        if confirmation.strip().upper() != customer.customer_number:
            raise ValidationFailed("Type the customer number to confirm the erasure.")
        blockers = await self._repo.blocking_activity(customer.id)
        if blockers:
            raise Conflict(
                "The data is still needed for work in progress; erase it once that is finished.",
                details={"reasons": blockers},
            )
        now = self._clock()
        users = await self._repo.users(customer.id)
        for user in users:
            user.email = erased_address(user.id)
            user.display_name = ERASED_NAME
            user.is_active = False
            # A random, never-shown password: the account can no longer be signed in to.
            user.password_hash = await self._hasher.hash_async(secrets.token_urlsafe(32))
            user.failed_login_count = 0
            user.locked_until = None
            await clear_second_factor(user, self._mfa, now)
            await self._sessions.revoke_all_for_user(user.id, reason="erased", now=now)
            await self._sessions.invalidate_reset_tokens(user.id, now)
            await self._repo.delete_idempotency_records(user.id)
        customer.full_name = ERASED_NAME
        customer.email = erased_address(customer.id)
        customer.phone = None
        customer.address = None
        customer.erased_at = now
        counts = await self._repo.anonymise_records(customer.id, now=now, placeholder=ERASED_TEXT)
        counts["users"] = len(users)
        await self._session.commit()
        await self._audit.record(
            "privacy.erase",
            outcome=AuditOutcome.SUCCESS,
            actor=principal,
            resource_type="customer",
            resource_id=customer.id,
            details=counts,
        )
        return ErasureReport(customer_id=customer.id, erased_at=now, counts=counts)

    # --- retention (worker) --------------------------------------------------------------------------
    async def expire_conversations(self, *, retention_days: int, limit: int = 200) -> int:
        """Erase the text of finished conversations older than the retention period.

        Runs inside the caller's transaction (the maintenance job commits).
        """
        if retention_days <= 0:
            return 0
        now = self._clock()
        ids = await self._repo.expired_conversations(
            now - timedelta(days=retention_days), limit=limit
        )
        await self._repo.erase_conversation_text(ids, now=now, placeholder=EXPIRED_TEXT)
        return len(ids)
