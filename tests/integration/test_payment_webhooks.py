"""Refunds through a payment provider: approval leaves the refund pending until a signed webhook."""

from __future__ import annotations

import json
import time
import uuid
from collections.abc import AsyncIterator, Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import httpx2
import pytest
from sqlalchemy import select

from aegis.bootstrap import AppContainer
from aegis.main import create_app
from aegis.models import AuditEvent, Payment, Refund
from aegis.security.webhooks import stripe_signature
from aegis.services.payments import PENDING, GatewayRefund
from tests.conftest import MANAGER, SOFIA, build_container, make_settings, seed

SECRET = "whsec_integration_0123456789"
Creds = dict[str, dict[str, str]]


@dataclass
class PendingGateway:
    """Stands in for Stripe: every refund is accepted and stays pending."""

    name: str = "fake-stripe"
    calls: list[dict[str, Any]] = field(default_factory=list)

    async def refund(
        self,
        *,
        payment_reference: str,
        amount_cents: int,
        idempotency_key: str,
        metadata: Mapping[str, str],
    ) -> GatewayRefund:
        self.calls.append(
            {
                "reference": payment_reference,
                "amount": amount_cents,
                "key": idempotency_key,
                "metadata": dict(metadata),
            }
        )
        return GatewayRefund(provider_refund_id="re_int_0001", status=PENDING)

    async def close(self) -> None:
        return None


@dataclass
class Stack:
    client: httpx2.AsyncClient
    container: AppContainer
    creds: Creds
    gateway: PendingGateway


@pytest.fixture
async def stack(tmp_path: Path) -> AsyncIterator[Stack]:
    container = await build_container(
        make_settings(
            payment_provider="stripe",
            stripe_api_key="rk_test_integration_key",
            stripe_webhook_secret=SECRET,
        )
    )
    await container.payments.close()  # the real Stripe client is replaced by the stand-in
    fake = PendingGateway()
    container.payments = fake
    try:
        creds = await seed(container, tmp_path, with_kb=False)
        app = create_app(container.settings, container=container)
        async with httpx2.AsyncClient(
            transport=httpx2.ASGITransport(app=app), base_url="http://testserver"
        ) as client:
            yield Stack(client, container, creds, fake)
    finally:
        await container.close()


async def bearer(stack: Stack, email: str) -> dict[str, str]:
    response = await stack.client.post(
        "/api/v1/auth/login", json={"email": email, "password": stack.creds[email]["password"]}
    )
    return {"Authorization": f"Bearer {response.json()['access_token']}"}


def signed(event: dict[str, Any], *, secret: str = SECRET) -> tuple[bytes, dict[str, str]]:
    body = json.dumps(event).encode()
    timestamp = int(time.time())
    return body, {
        "Stripe-Signature": f"t={timestamp},v1={stripe_signature(body, secret, timestamp)}",
        "Content-Type": "application/json",
    }


def refund_event(
    status: str, *, provider_id: str = "re_int_0001", number: str = ""
) -> dict[str, Any]:
    metadata = {"aegis_refund_number": number} if number else {}
    return {
        "id": "evt_1",
        "type": "refund.updated",
        "data": {
            "object": {
                "object": "refund",
                "id": provider_id,
                "status": status,
                "metadata": metadata,
            }
        },
    }


async def post_event(stack: Stack, body: bytes, headers: dict[str, str]) -> httpx2.Response:
    return await stack.client.post("/api/v1/webhooks/stripe", content=body, headers=headers)


async def test_approved_refund_completes_through_the_signed_webhook(stack: Stack) -> None:
    manager = await bearer(stack, MANAGER)
    sofia = await bearer(stack, SOFIA)
    own = (await stack.client.get("/api/v1/refunds", headers=sofia)).json()["items"]
    pending = next(r for r in own if r["refund_number"] == "RFD-100051")

    approved = await stack.client.post(
        f"/api/v1/refunds/{pending['id']}/decision", json={"approve": True}, headers=manager
    )
    assert approved.status_code == 200 and approved.json()["status"] == "processing"
    call = stack.gateway.calls[0]
    assert call["key"] == f"refund:{pending['id']}"
    assert call["metadata"] == {"aegis_refund_number": "RFD-100051"}

    body, headers = signed(refund_event("succeeded"))
    delivered = await post_event(stack, body, headers)
    assert delivered.status_code == 200 and delivered.json() == {
        "received": True,
        "result": "completed",
    }
    refund = (await stack.client.get(f"/api/v1/refunds/{pending['id']}", headers=sofia)).json()
    assert refund["status"] == "completed"
    async with stack.container.sessionmaker() as session:
        stored = await session.get(Refund, uuid.UUID(refund["id"]))
        assert stored is not None and stored.provider_refund_id == "re_int_0001"
        payment = await session.get(Payment, stored.payment_id)
        assert payment is not None and payment.status.value in {"refunded", "partially_refunded"}

    # Providers deliver events more than once, and out of order: nothing changes any more.
    assert (await post_event(stack, body, headers)).json()["result"] == "unchanged"
    late_body, late_headers = signed(refund_event("failed"))
    assert (await post_event(stack, late_body, late_headers)).json()["result"] == "unchanged"


async def test_failed_refunds_are_recorded_by_refund_number(stack: Stack) -> None:
    manager = await bearer(stack, MANAGER)
    listing = await stack.client.get(
        "/api/v1/refunds", params={"status": "pending_review"}, headers=manager
    )
    pending = listing.json()["items"][0]
    await stack.client.post(
        f"/api/v1/refunds/{pending['id']}/decision", json={"approve": True}, headers=manager
    )
    body, headers = signed(
        refund_event("canceled", provider_id="re_unknown_9", number=pending["refund_number"])
    )
    assert (await post_event(stack, body, headers)).json()["result"] == "failed"


async def test_forged_and_irrelevant_events_change_nothing(stack: Stack) -> None:
    body, _ = signed(refund_event("succeeded"))
    _, forged_headers = signed(refund_event("succeeded"), secret="whsec_attacker_guess")
    forged = await post_event(stack, body, forged_headers)
    assert forged.status_code == 400
    assert forged.headers["content-type"].startswith("application/problem+json")
    missing = await post_event(stack, body, {"Content-Type": "application/json"})
    assert missing.status_code == 400

    other_body, other_headers = signed({"type": "customer.created", "data": {"object": {}}})
    assert (await post_event(stack, other_body, other_headers)).json()["result"] == "ignored"
    unknown_body, unknown_headers = signed(refund_event("succeeded", provider_id="re_nobody"))
    assert (await post_event(stack, unknown_body, unknown_headers)).json()[
        "result"
    ] == "unknown_refund"
    async with stack.container.sessionmaker() as session:
        denied = (
            (
                await session.execute(
                    select(AuditEvent.outcome).where(AuditEvent.action == "payment.webhook")
                )
            )
            .scalars()
            .all()
        )
    assert [outcome.value for outcome in denied] == ["denied", "denied"]


async def test_webhook_is_unavailable_without_the_provider(client: httpx2.AsyncClient) -> None:
    response = await client.post(
        "/api/v1/webhooks/stripe",
        json={"type": "refund.updated"},
        headers={"Stripe-Signature": "t=1,v1=a"},
    )
    assert response.status_code == 404
