"""Payment provider adapters for refunds.

:class:`PaymentGateway` is the contract the refund flows use (manager approval, order
cancellation). Two implementations:

* :class:`SimulatedPaymentGateway` - development, tests and demos; moves no money. Production
  refuses it (see the settings).
* :class:`StripePaymentGateway` - creates refunds through the Stripe API.

Safety properties shared by both:

* every refund carries an idempotency key derived from our own refund record, and the provider
  returns the original result for a repeated key - a retried or double-clicked approval never
  refunds twice;
* results are normalised to ``succeeded`` / ``pending`` / ``failed``; a pending refund is
  finished later by the provider's signed webhook (:mod:`aegis.security.webhooks`);
* the Stripe adapter reaches only the configured host through the egress policy (HTTPS, no
  redirects, response size and type checks) and sends the secret key only in the
  ``Authorization`` header. A business refusal (4xx) becomes :class:`PaymentRejected` with the
  provider's error code; outages (5xx, timeouts, 429) become ``DependencyUnavailable`` so the
  approval can simply be retried later.
"""

from __future__ import annotations

import hashlib
import re
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any, Protocol

import httpx2

from aegis.core.egress import EgressPolicy, send_request
from aegis.core.errors import Conflict, DependencyUnavailable

SUCCEEDED = "succeeded"
PENDING = "pending"
FAILED = "failed"
_STRIPE_STATUS = {
    "succeeded": SUCCEEDED,
    "pending": PENDING,
    "requires_action": PENDING,
    "failed": FAILED,
    "canceled": FAILED,
}
_PROVIDER_ID = re.compile(r"^[A-Za-z0-9_]{3,64}$")


def normalize_refund_status(provider_status: object) -> str:
    """Map a provider's refund status to succeeded / pending / failed (unknown = pending)."""
    return _STRIPE_STATUS.get(str(provider_status), PENDING)


class PaymentRejected(Conflict):
    code = "payment_rejected"
    default_message = "The payment provider refused the refund."


@dataclass(frozen=True, slots=True)
class GatewayRefund:
    provider_refund_id: str
    status: str
    failure_code: str | None = None


class PaymentGateway(Protocol):
    name: str

    async def refund(
        self,
        *,
        payment_reference: str,
        amount_cents: int,
        idempotency_key: str,
        metadata: Mapping[str, str],
    ) -> GatewayRefund: ...

    async def close(self) -> None: ...


class SimulatedPaymentGateway:
    name = "simulated"

    def __init__(self) -> None:
        self._processed: dict[str, GatewayRefund] = {}

    async def refund(
        self,
        *,
        payment_reference: str,
        amount_cents: int,
        idempotency_key: str,
        metadata: Mapping[str, str],
    ) -> GatewayRefund:
        if amount_cents <= 0:
            msg = "refund amount must be positive"
            raise ValueError(msg)
        existing = self._processed.get(idempotency_key)
        if existing is not None:
            return existing
        digest = hashlib.sha256(f"{payment_reference}:{idempotency_key}".encode()).hexdigest()[:18]
        result = GatewayRefund(provider_refund_id=f"re_{digest}", status=SUCCEEDED)
        self._processed[idempotency_key] = result
        return result

    async def close(self) -> None:
        return None


class StripePaymentGateway:
    name = "stripe"

    def __init__(
        self,
        *,
        api_key: str,
        base_url: str,
        client: httpx2.AsyncClient,
        policy: EgressPolicy,
        max_response_bytes: int = 256_000,
    ) -> None:
        self._api_key = api_key
        self._url = base_url.rstrip("/") + "/v1/refunds"
        self._client = client
        self._policy = policy
        self._max_response_bytes = max_response_bytes

    @staticmethod
    def _target(payment_reference: str) -> tuple[str, str]:
        if payment_reference.startswith("pi_"):
            return "payment_intent", payment_reference
        if payment_reference.startswith(("ch_", "py_")):
            return "charge", payment_reference
        raise PaymentRejected(
            "This payment was not made through Stripe; refund it outside the platform.",
            log_message="payment reference is not a Stripe id",
        )

    async def refund(
        self,
        *,
        payment_reference: str,
        amount_cents: int,
        idempotency_key: str,
        metadata: Mapping[str, str],
    ) -> GatewayRefund:
        if amount_cents <= 0:
            msg = "refund amount must be positive"
            raise ValueError(msg)
        field, reference = self._target(payment_reference)
        form = {field: reference, "amount": str(amount_cents), "reason": "requested_by_customer"}
        form.update({f"metadata[{key}]": value for key, value in metadata.items()})
        response = await send_request(
            self._client,
            self._policy,
            self._url,
            headers={
                "Authorization": f"Bearer {self._api_key}",
                "Idempotency-Key": idempotency_key[:255],
            },
            form=form,
            max_response_bytes=self._max_response_bytes,
        )
        if response.status_code in (401, 403):
            raise DependencyUnavailable(log_message="stripe rejected the API key")
        if response.status_code == 429:
            raise DependencyUnavailable(log_message="stripe rate limit reached")
        if response.status_code >= 400:
            code = _error_code(response.body)
            raise PaymentRejected(
                f"The payment provider refused the refund ({code}).",
                log_message=f"stripe refused the refund: {code}",
                details={"provider_code": code},
            )
        body = response.body if isinstance(response.body, dict) else {}
        refund_id = body.get("id")
        if not isinstance(refund_id, str) or not _PROVIDER_ID.fullmatch(refund_id):
            raise DependencyUnavailable(log_message="stripe answered without a valid refund id")
        failure = body.get("failure_reason")
        return GatewayRefund(
            provider_refund_id=refund_id,
            status=normalize_refund_status(body.get("status")),
            failure_code=str(failure)[:40] if failure else None,
        )

    async def close(self) -> None:
        await self._client.aclose()


def _error_code(body: Any) -> str:
    error = body.get("error") if isinstance(body, dict) else None
    code = error.get("code") or error.get("type") if isinstance(error, dict) else None
    text = str(code or "unknown_error")
    return text if re.fullmatch(r"[a-z0-9_]{1,60}", text) else "unknown_error"


REFUND_EVENT_TYPES = frozenset(
    {"refund.created", "refund.updated", "refund.failed", "charge.refund.updated"}
)
_REFUND_NUMBER = re.compile(r"^RFD-\d{6,10}$")


@dataclass(frozen=True, slots=True)
class ProviderRefundUpdate:
    provider_refund_id: str | None
    refund_number: str | None
    status: str


def parse_stripe_refund_event(event: object) -> ProviderRefundUpdate | None:
    """The refund update inside a (verified) Stripe event, or None for anything else."""
    if not isinstance(event, dict) or event.get("type") not in REFUND_EVENT_TYPES:
        return None
    data = event.get("data")
    refund = data.get("object") if isinstance(data, dict) else None
    if not isinstance(refund, dict) or refund.get("object") != "refund":
        return None
    provider_id = refund.get("id")
    metadata = refund.get("metadata")
    number = metadata.get("aegis_refund_number") if isinstance(metadata, dict) else None
    update = ProviderRefundUpdate(
        provider_refund_id=provider_id
        if isinstance(provider_id, str) and _PROVIDER_ID.fullmatch(provider_id)
        else None,
        refund_number=number
        if isinstance(number, str) and _REFUND_NUMBER.fullmatch(number)
        else None,
        status=normalize_refund_status(refund.get("status")),
    )
    if update.provider_refund_id is None and update.refund_number is None:
        return None
    return update
