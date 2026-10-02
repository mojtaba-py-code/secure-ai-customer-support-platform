"""Signed webhooks from the payment provider.

The endpoint is public by necessity; the HMAC signature over the raw body (checked before any
parsing, with a replay window) is what authenticates the caller. Invalid signatures are audited
and counted as a security event. Only refund events change anything, and only in the idempotent
way :meth:`aegis.services.commerce.RefundService.apply_provider_update` allows.
"""

from __future__ import annotations

import json
import time

from fastapi import APIRouter, Request

from aegis.api.deps import ContainerDep, ServicesDep
from aegis.api.v1 import API_V1_PREFIX
from aegis.core.config import PaymentProviderName
from aegis.core.errors import BadRequest, NotFound
from aegis.domain.enums import AuditOutcome
from aegis.observability import metrics
from aegis.schemas.commerce import WebhookAck
from aegis.security.webhooks import WebhookSignatureError, verify_stripe_signature
from aegis.services.payments import parse_stripe_refund_event

router = APIRouter(prefix=f"{API_V1_PREFIX}/webhooks", tags=["webhooks"])


@router.post("/stripe", response_model=WebhookAck)
async def stripe_webhook(
    request: Request, container: ContainerDep, services: ServicesDep
) -> WebhookAck:
    """Refund outcomes reported by Stripe (signature-verified)."""
    settings = container.settings
    secret = settings.stripe_webhook_secret
    if settings.payment_provider is not PaymentProviderName.STRIPE or secret is None:
        raise NotFound
    payload = await request.body()
    try:
        verify_stripe_signature(
            payload,
            request.headers.get("stripe-signature"),
            secret.get_secret_value(),
            now=time.time(),
        )
    except WebhookSignatureError as exc:
        metrics.security_event("webhook_signature_invalid")
        await container.audit.record(
            "payment.webhook",
            outcome=AuditOutcome.DENIED,
            actor_role="payment_provider",
            details={"reason": str(exc)},
        )
        raise BadRequest("Invalid webhook signature.", log_message=str(exc)) from exc
    try:
        event = json.loads(payload)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise BadRequest("The webhook body is not valid JSON.") from exc
    update = parse_stripe_refund_event(event)
    if update is None:
        return WebhookAck(received=True, result="ignored")
    result = await services.refunds.apply_provider_update(
        provider_refund_id=update.provider_refund_id,
        refund_number=update.refund_number,
        provider_status=update.status,
    )
    return WebhookAck(received=True, result=result)
