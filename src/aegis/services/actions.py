"""Customer-confirmed actions (refund requests, order cancellations).

The assistant can only *propose* a state-changing action, and only after the deterministic
policy says it is allowed. Execution requires a separate, authenticated API call by the
customer - a prompt-injected model cannot confirm on the customer's behalf. On confirmation:

1. ownership is re-checked (the action must belong to this user and conversation);
2. an atomic ``PENDING -> EXECUTING`` transition guarantees at most one execution even when the
   customer double-clicks or retries;
3. the business rules are evaluated *again* against locked rows (the order may have shipped
   since the proposal) - time-of-check/time-of-use safe;
4. database constraints (one open refund per order) back up the application checks.
"""

from __future__ import annotations

import uuid
from datetime import timedelta
from typing import Any

from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from aegis.core.errors import AegisError, Conflict, NotFound, PermissionDenied, ValidationFailed
from aegis.core.time import Clock, utc_now
from aegis.domain.enums import ActionStatus, ActionType, AuditOutcome, RefundReason, RequestSource
from aegis.domain.policies import cancellation_blockers
from aegis.models import PendingAction
from aegis.repositories.commerce import RefundRepository
from aegis.repositories.support import ConversationRepository, PendingActionRepository
from aegis.security.principal import Principal
from aegis.security.rbac import Permission
from aegis.security.redaction import redact_for_storage
from aegis.security.text import normalize_text, truncate
from aegis.services.audit import AuditService
from aegis.services.authz import require
from aegis.services.commerce import OrderService, RefundService, latest_payment


def format_money(cents: int, currency: str) -> str:
    return f"{cents / 100:,.2f} {currency}"


class PendingActionService:
    def __init__(
        self,
        session: AsyncSession,
        *,
        orders: OrderService,
        refunds: RefundService,
        audit: AuditService,
        ttl_seconds: int,
        clock: Clock = utc_now,
    ) -> None:
        self._session = session
        self._actions = PendingActionRepository(session)
        self._conversations = ConversationRepository(session)
        self._refund_repo = RefundRepository(session)
        self._orders = orders
        self._refunds = refunds
        self._audit = audit
        self._ttl = timedelta(seconds=ttl_seconds)
        self._clock = clock

    # --- proposals (called by the assistant's tools) -----------------------------------------------
    async def propose_refund(
        self,
        principal: Principal,
        *,
        conversation_id: uuid.UUID,
        order_number: str,
        reason: RefundReason,
        note: str | None,
    ) -> PendingAction:
        require(principal, Permission.REFUND_REQUEST_OWN)
        order, eligibility = await self._orders.refund_eligibility(principal, order_number)
        if not eligibility.eligible:
            raise ValidationFailed(
                "This order is not eligible for a refund.",
                details={"reasons": list(eligibility.reasons)},
            )
        clean_note = truncate(redact_for_storage(normalize_text(note)).text, 500) if note else None
        return await self._propose(
            principal,
            conversation_id=conversation_id,
            action_type=ActionType.REFUND_REQUEST,
            dedupe_key=f"refund:{order.id}",
            params={
                "order_id": str(order.id),
                "order_number": order.order_number,
                "amount_cents": eligibility.max_refundable_cents,
                "currency": order.currency,
                "reason": reason.value,
                "note": clean_note,
            },
            summary=(
                f"Request a refund of {format_money(eligibility.max_refundable_cents, order.currency)} "
                f"for order {order.order_number} (reason: {reason.value.replace('_', ' ')})"
            ),
        )

    async def propose_cancellation(
        self, principal: Principal, *, conversation_id: uuid.UUID, order_number: str
    ) -> PendingAction:
        require(principal, Permission.ORDER_CANCEL_OWN)
        order = await self._orders.get_order(principal, order_number)
        blockers = cancellation_blockers(order.status)
        if blockers:
            raise ValidationFailed(
                "This order can no longer be cancelled.", details={"reasons": list(blockers)}
            )
        return await self._propose(
            principal,
            conversation_id=conversation_id,
            action_type=ActionType.ORDER_CANCELLATION,
            dedupe_key=f"cancel:{order.id}",
            params={"order_id": str(order.id), "order_number": order.order_number},
            summary=f"Cancel order {order.order_number} (status: {order.status.value})",
        )

    async def _propose(
        self,
        principal: Principal,
        *,
        conversation_id: uuid.UUID,
        action_type: ActionType,
        dedupe_key: str,
        params: dict[str, Any],
        summary: str,
    ) -> PendingAction:
        if principal.customer_id is None:
            raise PermissionDenied
        conversation = await self._conversations.get_for_user(conversation_id, principal.user_id)
        if conversation is None:
            raise NotFound
        now = self._clock()
        existing = await self._actions.get_open_by_dedupe(dedupe_key)
        if existing is not None:
            if existing.user_id != principal.user_id:
                raise Conflict("Another request for this order is already open.")
            if existing.expires_at > now:
                return existing
            existing.status = ActionStatus.EXPIRED
            existing.decided_at = now
            await self._session.flush()
        action = self._actions.add(
            PendingAction(
                conversation_id=conversation_id,
                user_id=principal.user_id,
                customer_id=principal.customer_id,
                action_type=action_type,
                status=ActionStatus.PENDING,
                params=params,
                summary=summary[:300],
                dedupe_key=dedupe_key,
                created_at=now,
                expires_at=now + self._ttl,
            )
        )
        try:
            await self._session.commit()
        except IntegrityError as exc:
            await self._session.rollback()
            raced = await self._actions.get_open_by_dedupe(dedupe_key)
            if raced is not None and raced.user_id == principal.user_id:
                return raced
            raise Conflict("Another request for this order is already open.") from exc
        await self._audit.record(
            "action.propose",
            outcome=AuditOutcome.SUCCESS,
            actor=principal,
            resource_type="pending_action",
            resource_id=action.id,
            details={"type": action_type.value},
        )
        return action

    # --- customer decisions -----------------------------------------------------------------------------
    async def list_for_conversation(
        self, principal: Principal, conversation_id: uuid.UUID
    ) -> list[PendingAction]:
        if principal.has(Permission.CONVERSATION_READ_ANY):
            conversation = await self._conversations.get(conversation_id)
        else:
            conversation = await self._conversations.get_for_user(
                conversation_id, principal.user_id
            )
        if conversation is None:
            raise NotFound
        return await self._actions.list_for_conversation(conversation.id)

    async def _owned(
        self, principal: Principal, conversation_id: uuid.UUID, action_id: uuid.UUID
    ) -> PendingAction:
        require(principal, Permission.ACTION_CONFIRM_OWN)
        action = await self._actions.get_for_user(
            action_id, conversation_id=conversation_id, user_id=principal.user_id
        )
        if action is None:
            raise NotFound
        return action

    async def decline(
        self, principal: Principal, conversation_id: uuid.UUID, action_id: uuid.UUID
    ) -> PendingAction:
        action = await self._owned(principal, conversation_id, action_id)
        if action.status is ActionStatus.PENDING:
            action.status = ActionStatus.DECLINED
            action.decided_at = self._clock()
            await self._session.commit()
            await self._audit.record(
                "action.decline",
                outcome=AuditOutcome.SUCCESS,
                actor=principal,
                resource_type="pending_action",
                resource_id=action.id,
            )
        return action

    async def confirm(
        self, principal: Principal, conversation_id: uuid.UUID, action_id: uuid.UUID
    ) -> PendingAction:
        action = await self._owned(principal, conversation_id, action_id)
        if action.status in (ActionStatus.EXECUTED, ActionStatus.FAILED, ActionStatus.DECLINED):
            return action  # idempotent: a repeated confirmation returns the recorded outcome
        if action.status is ActionStatus.EXECUTING:
            raise Conflict("This request is already being processed.")
        now = self._clock()
        if action.status is ActionStatus.EXPIRED or action.expires_at <= now:
            if action.status is ActionStatus.PENDING:
                action.status = ActionStatus.EXPIRED
                action.decided_at = now
                await self._session.commit()
            raise Conflict("This request has expired. Please ask the assistant again.")
        if not await self._actions.claim_for_execution(action.id, now):
            await self._session.rollback()
            await self._session.refresh(action)
            return action
        await self._session.commit()

        try:
            result = await self._execute(principal, action)
            action.status = ActionStatus.EXECUTED
            action.result = result
            await self._session.commit()
            outcome = AuditOutcome.SUCCESS
        except (AegisError, IntegrityError) as exc:
            await self._session.rollback()
            await self._session.refresh(action)
            action.status = ActionStatus.FAILED
            public = (
                exc.public_message
                if isinstance(exc, AegisError)
                else "The request conflicts with an existing one."
            )
            code = exc.code if isinstance(exc, AegisError) else "conflict"
            action.result = {"error": code, "message": public}
            await self._session.commit()
            outcome = AuditOutcome.FAILURE
        await self._audit.record(
            "action.confirm",
            outcome=outcome,
            actor=principal,
            resource_type="pending_action",
            resource_id=action.id,
            details={"type": action.action_type.value, "status": action.status.value},
        )
        return action

    async def _execute(self, principal: Principal, action: PendingAction) -> dict[str, Any]:
        if principal.customer_id is None:
            raise PermissionDenied
        order_id = uuid.UUID(str(action.params["order_id"]))
        order = await self._orders.locked_order_for_customer(principal.customer_id, order_id)
        if action.action_type is ActionType.ORDER_CANCELLATION:
            return await self._orders.cancel(principal, order)

        refunds = await self._refund_repo.list_for_order(order.id)
        eligibility = self._orders.evaluate(order, refunds)
        if not eligibility.eligible:
            raise ValidationFailed(
                "This order is no longer eligible for a refund.",
                details={"reasons": list(eligibility.reasons)},
            )
        payment = latest_payment(order)
        if payment is None:
            raise ValidationFailed("No captured payment was found for this order.")
        amount = min(int(action.params["amount_cents"]), eligibility.max_refundable_cents)
        refund = self._refunds.create_request(
            principal,
            order=order,
            payment=payment,
            amount_cents=amount,
            reason=RefundReason(str(action.params["reason"])),
            note=action.params.get("note"),
            source=RequestSource.AI_AGENT,
            idempotency_key=f"action:{action.id}",
        )
        await self._session.flush()
        return {
            "refund_number": refund.refund_number,
            "order_number": order.order_number,
            "amount_cents": amount,
            "currency": refund.currency,
            "status": refund.status.value,
        }
