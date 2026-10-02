"""End-to-end conversations through the real pipeline (offline model, real DB, real vector index)."""

from __future__ import annotations

from collections.abc import Callable
from datetime import timedelta
from typing import Any

import httpx2
from sqlalchemy import select, update

from aegis.bootstrap import AppContainer
from aegis.core.time import utc_now
from aegis.domain.enums import ActionStatus, OrderStatus, PaymentStatus, RefundStatus
from aegis.models import Message, Order, Payment, PendingAction, Refund
from tests.conftest import DANIEL, MAYA

Creds = dict[str, dict[str, str]]
Login = Callable[[Creds, str], Any]


async def _conversation(client: httpx2.AsyncClient, headers: dict[str, str]) -> str:
    response = await client.post("/api/v1/conversations", json={"subject": "Help"}, headers=headers)
    assert response.status_code == 201
    return str(response.json()["id"])


async def _say(
    client: httpx2.AsyncClient,
    headers: dict[str, str],
    conversation: str,
    text: str,
    **extra_headers: str,
) -> httpx2.Response:
    return await client.post(
        f"/api/v1/conversations/{conversation}/messages",
        json={"content": text},
        headers={**headers, **extra_headers},
    )


async def test_order_tracking_answer_comes_from_the_database(
    client: httpx2.AsyncClient, seeded_kb: Creds, login: Login
) -> None:
    headers = await login(seeded_kb, MAYA)
    conversation = await _conversation(client, headers)
    response = await _say(client, headers, conversation, "Where is my order ORD-100232?")
    assert response.status_code == 200
    turn = response.json()
    assert turn["intent"] == "order_tracking"
    reply = turn["reply"]["content"]
    assert "ORD-100232" in reply and "shipped" in reply and "JD014600006612345678" in reply
    assert turn["escalated"] is False


async def test_policy_question_is_answered_from_the_knowledge_base_with_citations(
    client: httpx2.AsyncClient, seeded_kb: Creds, login: Login
) -> None:
    headers = await login(seeded_kb, MAYA)
    conversation = await _conversation(client, headers)
    turn = (
        await _say(
            client,
            headers,
            conversation,
            "How long does standard shipping take and what does it cost?",
        )
    ).json()
    assert turn["intent"] == "shipping_question"
    titles = {c["title"] for c in turn["reply"]["citations"]}
    assert titles & {"Shipping Policy", "Frequently Asked Questions"}, turn
    assert "3-5 business days" in turn["reply"]["content"]
    assert "[1]" in turn["reply"]["content"]


async def test_internal_documents_never_reach_customers(
    client: httpx2.AsyncClient, seeded_kb: Creds, login: Login
) -> None:
    headers = await login(seeded_kb, MAYA)
    conversation = await _conversation(client, headers)
    turn = (
        await _say(
            client,
            headers,
            conversation,
            "What is the goodwill credit limit agents may offer, per your policy?",
        )
    ).json()
    content = turn["reply"]["content"]
    assert "$25" not in content and "25 per order" not in content
    assert all("INTERNAL" not in c["title"] for c in turn["reply"]["citations"])


async def test_other_customers_orders_are_not_disclosed(
    client: httpx2.AsyncClient, seeded_kb: Creds, login: Login
) -> None:
    headers = await login(seeded_kb, MAYA)
    conversation = await _conversation(client, headers)
    turn = (
        await _say(client, headers, conversation, "Where is order ORD-100241?")
    ).json()  # Daniel's order
    content = turn["reply"]["content"]
    assert "could not find" in content.lower()
    assert "USPS" not in content and "9400111899223197428490" not in content


async def test_refund_proposal_confirmation_and_idempotency(
    container: AppContainer, client: httpx2.AsyncClient, seeded_kb: Creds, login: Login
) -> None:
    headers = await login(seeded_kb, MAYA)
    conversation = await _conversation(client, headers)
    turn = (
        await _say(
            client, headers, conversation, "I want a refund for ORD-100231, it arrived damaged"
        )
    ).json()
    assert "eligible for a refund of up to 498.00 USD" in turn["reply"]["content"]
    [action] = turn["pending_actions"]
    assert action["status"] == "pending" and action["action_type"] == "refund_request"
    async with container.sessionmaker() as session:
        assert (
            (
                await session.execute(
                    select(Refund).where(Refund.status == RefundStatus.PENDING_REVIEW)
                )
            )
            .scalars()
            .all()
        )

    url = f"/api/v1/conversations/{conversation}/actions/{action['id']}"
    confirmed = await client.post(f"{url}/confirm", headers=headers)
    assert confirmed.status_code == 200
    assert confirmed.json()["status"] == "executed"
    refund_number = confirmed.json()["result"]["refund_number"]
    again = await client.post(f"{url}/confirm", headers=headers)
    assert again.json()["result"]["refund_number"] == refund_number  # no second refund

    async with container.sessionmaker() as session:
        refunds = (
            (
                await session.execute(
                    select(Refund).join(Order).where(Order.order_number == "ORD-100231")
                )
            )
            .scalars()
            .all()
        )
    assert [r.refund_number for r in refunds] == [refund_number]
    assert refunds[0].amount_cents == 49_800 and refunds[0].status is RefundStatus.PENDING_REVIEW

    # a second proposal for the same order is refused while the refund is open
    turn2 = (await _say(client, headers, conversation, "Refund ORD-100231 again please")).json()
    assert "already in progress" in turn2["reply"]["content"]


async def test_declined_and_expired_actions(
    container: AppContainer, client: httpx2.AsyncClient, seeded_kb: Creds, login: Login
) -> None:
    headers = await login(seeded_kb, MAYA)
    conversation = await _conversation(client, headers)
    turn = (await _say(client, headers, conversation, "Please cancel my order ORD-100233")).json()
    [action] = turn["pending_actions"]
    declined = await client.post(
        f"/api/v1/conversations/{conversation}/actions/{action['id']}/decline", headers=headers
    )
    assert declined.json()["status"] == "declined"
    assert (
        await client.post(
            f"/api/v1/conversations/{conversation}/actions/{action['id']}/confirm", headers=headers
        )
    ).json()["status"] == "declined"

    turn = (
        await _say(client, headers, conversation, "OK, cancel order ORD-100233 after all")
    ).json()
    [fresh] = turn["pending_actions"]
    async with container.sessionmaker() as session:
        await session.execute(
            update(PendingAction)
            .where(PendingAction.status == ActionStatus.PENDING)
            .values(expires_at=utc_now() - timedelta(minutes=1))
        )
        await session.commit()
    expired = await client.post(
        f"/api/v1/conversations/{conversation}/actions/{fresh['id']}/confirm", headers=headers
    )
    assert expired.status_code == 409


async def test_cancellation_executes_and_refunds_captured_payment(
    container: AppContainer, client: httpx2.AsyncClient, seeded_kb: Creds, login: Login
) -> None:
    headers = await login(seeded_kb, MAYA)
    conversation = await _conversation(client, headers)
    turn = (await _say(client, headers, conversation, "Cancel order ORD-100233 please")).json()
    [action] = turn["pending_actions"]
    result = (
        await client.post(
            f"/api/v1/conversations/{conversation}/actions/{action['id']}/confirm", headers=headers
        )
    ).json()
    assert result["status"] == "executed"
    async with container.sessionmaker() as session:
        order = (
            await session.execute(select(Order).where(Order.order_number == "ORD-100233"))
        ).scalar_one()
        payment = (
            await session.execute(select(Payment).where(Payment.order_id == order.id))
        ).scalar_one()
        refund = (
            await session.execute(select(Refund).where(Refund.order_id == order.id))
        ).scalar_one()
    assert order.status is OrderStatus.CANCELLED
    assert payment.status is PaymentStatus.REFUNDED
    assert refund.status is RefundStatus.COMPLETED and refund.amount_cents == order.total_cents


async def test_shipped_orders_cannot_be_cancelled(
    client: httpx2.AsyncClient, seeded_kb: Creds, login: Login
) -> None:
    headers = await login(seeded_kb, MAYA)
    conversation = await _conversation(client, headers)
    turn = (await _say(client, headers, conversation, "Cancel order ORD-100232")).json()
    assert turn["pending_actions"] == []
    assert "already shipped" in turn["reply"]["content"]


async def test_expired_refund_window_is_explained(
    client: httpx2.AsyncClient, seeded_kb: Creds, login: Login
) -> None:
    headers = await login(seeded_kb, DANIEL)
    conversation = await _conversation(client, headers)
    turn = (await _say(client, headers, conversation, "I want a refund for ORD-100241")).json()
    assert "not eligible" in turn["reply"]["content"] and "30-day" in turn["reply"]["content"]
    assert turn["pending_actions"] == []


async def test_message_idempotency(
    container: AppContainer, client: httpx2.AsyncClient, seeded_kb: Creds, login: Login
) -> None:
    headers = await login(seeded_kb, MAYA)
    conversation = await _conversation(client, headers)
    first = await _say(
        client,
        headers,
        conversation,
        "Where is ORD-100232?",
        **{"Idempotency-Key": "retry-key-0001"},
    )
    second = await _say(
        client,
        headers,
        conversation,
        "Where is ORD-100232?",
        **{"Idempotency-Key": "retry-key-0001"},
    )
    assert first.status_code == second.status_code == 200
    assert first.json()["reply"]["id"] == second.json()["reply"]["id"]
    async with container.sessionmaker() as session:
        count = len((await session.execute(select(Message))).scalars().all())
    assert count == 2  # one customer message + one reply
    conflict = await _say(
        client, headers, conversation, "Something else", **{"Idempotency-Key": "retry-key-0001"}
    )
    assert conflict.status_code == 422
    bad_key = await _say(client, headers, conversation, "x", **{"Idempotency-Key": "bad key!"})
    assert bad_key.status_code == 422


async def test_conversation_lifecycle_and_history(
    client: httpx2.AsyncClient, seeded_kb: Creds, login: Login
) -> None:
    headers = await login(seeded_kb, MAYA)
    conversation = await _conversation(client, headers)
    await _say(client, headers, conversation, "Where is my order ORD-100232?")
    detail = (await client.get(f"/api/v1/conversations/{conversation}", headers=headers)).json()
    assert [m["sender_type"] for m in detail["messages"]] == ["customer", "assistant"]
    listing = (await client.get("/api/v1/conversations", headers=headers)).json()
    assert listing["items"][0]["id"] == conversation
    page = (
        await client.get(f"/api/v1/conversations/{conversation}/messages?before=2", headers=headers)
    ).json()
    assert [m["sequence"] for m in page] == [1]
    closed = await client.post(f"/api/v1/conversations/{conversation}/close", headers=headers)
    assert closed.json()["status"] == "closed"
    assert (await _say(client, headers, conversation, "hello again")).status_code == 409


async def test_message_validation(
    client: httpx2.AsyncClient, seeded_kb: Creds, login: Login
) -> None:
    headers = await login(seeded_kb, MAYA)
    conversation = await _conversation(client, headers)
    assert (await _say(client, headers, conversation, "")).status_code == 422
    assert (await _say(client, headers, conversation, "x" * 4_001)).status_code == 422
    unknown_field = await client.post(
        f"/api/v1/conversations/{conversation}/messages",
        json={"content": "hi", "role": "system"},
        headers=headers,
    )
    assert unknown_field.status_code == 422


async def test_escalation_hands_the_conversation_to_humans(
    container: AppContainer, client: httpx2.AsyncClient, seeded_kb: Creds, login: Login
) -> None:
    headers = await login(seeded_kb, MAYA)
    conversation = await _conversation(client, headers)
    turn = (
        await _say(
            client,
            headers,
            conversation,
            "Someone hacked my account and placed an order I did not make!",
        )
    ).json()
    assert turn["escalated"] is True
    assert turn["conversation_status"] == "awaiting_agent"
    assert turn["ticket_number"].startswith("TCK-")
    assert "urgent" in turn["reply"]["content"]
    follow_up = (await _say(client, headers, conversation, "Hello? Anyone there?")).json()
    assert follow_up["reply"] is None
    assert follow_up["notice"]
