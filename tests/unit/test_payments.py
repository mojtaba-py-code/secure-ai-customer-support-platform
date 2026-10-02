"""Payment adapters and signed webhooks (the Stripe API is simulated with a mock transport)."""

from __future__ import annotations

import json
from collections.abc import Callable
from urllib.parse import parse_qs

import httpx2
import pytest

from aegis.core.egress import EgressPolicy
from aegis.core.errors import DependencyUnavailable, EgressDenied
from aegis.security.webhooks import (
    WebhookSignatureError,
    stripe_signature,
    verify_stripe_signature,
)
from aegis.services.payments import (
    FAILED,
    PENDING,
    SUCCEEDED,
    PaymentRejected,
    SimulatedPaymentGateway,
    StripePaymentGateway,
    normalize_refund_status,
    parse_stripe_refund_event,
)

Handler = Callable[[httpx2.Request], httpx2.Response]
SECRET = "whsec_test_0123456789abcdef"


def gateway(handler: Handler, *, allowed_host: str = "api.stripe.com") -> StripePaymentGateway:
    return StripePaymentGateway(
        api_key="rk_test_restricted_key",
        base_url="https://api.stripe.com",
        client=httpx2.AsyncClient(transport=httpx2.MockTransport(handler)),
        policy=EgressPolicy([allowed_host]),
    )


def json_response(status: int, body: object) -> httpx2.Response:
    return httpx2.Response(status, json=body)


async def refund(adapter: StripePaymentGateway, reference: str = "pi_3Q0abc") -> object:
    try:
        return await adapter.refund(
            payment_reference=reference,
            amount_cents=1_500,
            idempotency_key="refund:7f3c",
            metadata={"aegis_refund_number": "RFD-12345678"},
        )
    finally:
        await adapter.close()


async def test_stripe_refund_request_shape() -> None:
    seen: list[httpx2.Request] = []

    def handler(request: httpx2.Request) -> httpx2.Response:
        seen.append(request)
        return json_response(200, {"id": "re_3Q0xyz", "object": "refund", "status": "pending"})

    result = await refund(gateway(handler))
    request = seen[0]
    assert request.method == "POST" and str(request.url) == "https://api.stripe.com/v1/refunds"
    assert request.headers["authorization"] == "Bearer rk_test_restricted_key"
    assert request.headers["idempotency-key"] == "refund:7f3c"
    assert request.headers["content-type"].startswith("application/x-www-form-urlencoded")
    form = parse_qs(request.content.decode())
    assert form["payment_intent"] == ["pi_3Q0abc"] and form["amount"] == ["1500"]
    assert form["metadata[aegis_refund_number]"] == ["RFD-12345678"]
    assert result.provider_refund_id == "re_3Q0xyz" and result.status == PENDING  # type: ignore[attr-defined]


async def test_charge_references_use_the_charge_parameter() -> None:
    seen: list[dict[str, list[str]]] = []

    def handler(request: httpx2.Request) -> httpx2.Response:
        seen.append(parse_qs(request.content.decode()))
        return json_response(200, {"id": "re_1", "status": "succeeded"})

    result = await refund(gateway(handler), reference="ch_3Q0abc")
    assert seen[0]["charge"] == ["ch_3Q0abc"] and "payment_intent" not in seen[0]
    assert result.status == SUCCEEDED  # type: ignore[attr-defined]


@pytest.mark.parametrize(
    ("status", "expected"),
    [
        ("succeeded", SUCCEEDED),
        ("pending", PENDING),
        ("requires_action", PENDING),
        ("failed", FAILED),
        ("canceled", FAILED),
        ("something-new", PENDING),
        (None, PENDING),
    ],
)
def test_status_normalisation(status: object, expected: str) -> None:
    assert normalize_refund_status(status) == expected


async def test_business_refusals_carry_the_provider_code() -> None:
    def handler(request: httpx2.Request) -> httpx2.Response:
        return json_response(
            400, {"error": {"type": "invalid_request_error", "code": "charge_already_refunded"}}
        )

    with pytest.raises(PaymentRejected) as info:
        await refund(gateway(handler))
    assert info.value.details == {"provider_code": "charge_already_refunded"}
    assert "charge_already_refunded" in info.value.public_message


@pytest.mark.parametrize(
    "response",
    [
        httpx2.Response(401, json={"error": {"type": "authentication_error"}}),
        httpx2.Response(429, json={"error": {"type": "rate_limit_error"}}),
        httpx2.Response(500, json={"error": {"type": "api_error"}}),
        httpx2.Response(302, headers={"location": "https://evil.example/"}),
        httpx2.Response(200, text="<html>not json</html>", headers={"content-type": "text/html"}),
        httpx2.Response(200, json={"status": "succeeded"}),  # no refund id
        httpx2.Response(200, json={"id": "re_1; DROP", "status": "succeeded"}),
    ],
)
async def test_outages_and_malformed_answers_are_retryable(response: httpx2.Response) -> None:
    with pytest.raises(DependencyUnavailable):
        await refund(gateway(lambda request: response))


async def test_non_stripe_payments_are_refused_before_any_request() -> None:
    def handler(request: httpx2.Request) -> httpx2.Response:
        pytest.fail("no request may be sent")

    with pytest.raises(PaymentRejected):
        await refund(gateway(handler), reference="PAYID-L7QX")


async def test_only_the_configured_host_is_reachable() -> None:
    def handler(request: httpx2.Request) -> httpx2.Response:
        pytest.fail("no request may be sent")

    with pytest.raises(EgressDenied):
        await refund(gateway(handler, allowed_host="api.other.example"))


async def test_simulated_gateway_is_idempotent() -> None:
    simulated = SimulatedPaymentGateway()
    first = await simulated.refund(
        payment_reference="pi_demo", amount_cents=500, idempotency_key="k1", metadata={}
    )
    again = await simulated.refund(
        payment_reference="pi_demo", amount_cents=500, idempotency_key="k1", metadata={}
    )
    other = await simulated.refund(
        payment_reference="pi_demo", amount_cents=500, idempotency_key="k2", metadata={}
    )
    assert first == again and first.provider_refund_id != other.provider_refund_id
    with pytest.raises(ValueError, match="positive"):
        await simulated.refund(
            payment_reference="pi_demo", amount_cents=0, idempotency_key="k3", metadata={}
        )


# --- webhook signatures -------------------------------------------------------------------------
NOW = 1_800_000_000
PAYLOAD = b'{"type":"refund.updated"}'


def header(payload: bytes = PAYLOAD, *, secret: str = SECRET, timestamp: int = NOW) -> str:
    return f"t={timestamp},v1={stripe_signature(payload, secret, timestamp)}"


def test_valid_signature_is_accepted() -> None:
    verify_stripe_signature(PAYLOAD, header(), SECRET, now=NOW + 10)
    rotated = f"t={NOW},v1={'0' * 64},v1={stripe_signature(PAYLOAD, SECRET, NOW)}"
    verify_stripe_signature(PAYLOAD, rotated, SECRET, now=NOW)


@pytest.mark.parametrize(
    ("payload", "signature", "now"),
    [
        (PAYLOAD, header(secret="whsec_wrong_secret"), NOW),
        (b'{"type":"refund.updated","x":1}', header(), NOW),  # body tampered after signing
        (PAYLOAD, header(), NOW + 301),  # replayed too late
        (PAYLOAD, header(timestamp=NOW + 400), NOW),  # from the future
        (PAYLOAD, None, NOW),
        (PAYLOAD, "", NOW),
        (PAYLOAD, "v1=abc", NOW),
        (PAYLOAD, f"t={NOW}", NOW),
        (PAYLOAD, f"t=abc,v1={'a' * 64}", NOW),
        (PAYLOAD, f"t={NOW},v1=ä" + "a" * 63, NOW),
        (PAYLOAD, "t=1," + "v1=a," * 300, NOW),
    ],
)
def test_invalid_signatures_are_rejected(payload: bytes, signature: str | None, now: int) -> None:
    with pytest.raises(WebhookSignatureError):
        verify_stripe_signature(payload, signature, SECRET, now=now)


def test_refund_event_parsing() -> None:
    event = {
        "type": "refund.updated",
        "data": {
            "object": {
                "object": "refund",
                "id": "re_3Q0xyz",
                "status": "succeeded",
                "metadata": {"aegis_refund_number": "RFD-12345678"},
            }
        },
    }
    update = parse_stripe_refund_event(json.loads(json.dumps(event)))
    assert update is not None
    assert (update.provider_refund_id, update.refund_number, update.status) == (
        "re_3Q0xyz",
        "RFD-12345678",
        SUCCEEDED,
    )
    assert parse_stripe_refund_event({**event, "type": "customer.created"}) is None
    assert parse_stripe_refund_event({"type": "refund.updated", "data": {"object": {}}}) is None
    assert parse_stripe_refund_event([]) is None
    no_ids = {
        "type": "refund.updated",
        "data": {
            "object": {"object": "refund", "id": "bad id", "metadata": {"aegis_refund_number": "x"}}
        },
    }
    assert parse_stripe_refund_event(no_ids) is None
