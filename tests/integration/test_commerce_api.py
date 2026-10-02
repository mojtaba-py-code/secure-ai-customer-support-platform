from __future__ import annotations

from collections.abc import Callable
from typing import Any

import httpx2
import pytest
from sqlalchemy import select

from aegis.bootstrap import AppContainer
from aegis.models import SupportTicket
from tests.conftest import AGENT, DANIEL, MANAGER, MAYA, SOFIA

Creds = dict[str, dict[str, str]]
Login = Callable[[Creds, str], Any]


async def test_customers_see_only_their_orders(
    client: httpx2.AsyncClient, seeded: Creds, login: Login
) -> None:
    headers = await login(seeded, MAYA)
    orders = (await client.get("/api/v1/orders", headers=headers)).json()["items"]
    assert {o["order_number"] for o in orders} == {"ORD-100231", "ORD-100232", "ORD-100233"}
    own = await client.get("/api/v1/orders/ORD-100231", headers=headers)
    assert own.status_code == 200
    body = own.json()
    assert body["payment"]["card_last4"] and len(body["payment"]["card_last4"]) == 4
    assert "shipping_address" not in body and "provider_reference" not in str(body)
    foreign = await client.get("/api/v1/orders/ORD-100241", headers=headers)
    assert foreign.status_code == 404
    missing = await client.get("/api/v1/orders/ORD-999999", headers=headers)
    assert missing.status_code == 404
    assert foreign.json()["detail"] == missing.json()["detail"]  # indistinguishable


async def test_staff_can_read_any_order_and_filter_by_customer(
    client: httpx2.AsyncClient, seeded: Creds, login: Login
) -> None:
    headers = await login(seeded, AGENT)
    assert (await client.get("/api/v1/orders/ORD-100241", headers=headers)).status_code == 200
    everything = (await client.get("/api/v1/orders?limit=100", headers=headers)).json()["items"]
    assert len(everything) == 15


async def test_order_number_path_is_validated(
    client: httpx2.AsyncClient, seeded: Creds, login: Login
) -> None:
    headers = await login(seeded, MAYA)
    for probe in (
        "ORD-1' OR '1'='1",
        "ORD-100231;DROP TABLE orders",
        "..%2F..%2Fadmin",
        "ord-100231x",
    ):
        response = await client.get(f"/api/v1/orders/{probe}", headers=headers)
        assert response.status_code in (404, 422), probe


async def test_ticket_creation_listing_and_idempotency(
    container: AppContainer, client: httpx2.AsyncClient, seeded: Creds, login: Login
) -> None:
    headers = await login(seeded, MAYA)
    body = {
        "subject": "Remote missing",
        "description": "The soundbar box had no remote control inside.",
    }
    first = await client.post(
        "/api/v1/support/tickets",
        json=body,
        headers={**headers, "Idempotency-Key": "ticket-key-001"},
    )
    second = await client.post(
        "/api/v1/support/tickets",
        json=body,
        headers={**headers, "Idempotency-Key": "ticket-key-001"},
    )
    assert first.status_code == 201 and second.status_code == 201
    assert first.json()["id"] == second.json()["id"]
    async with container.sessionmaker() as session:
        tickets = (
            (
                await session.execute(
                    select(SupportTicket).where(SupportTicket.subject == "Remote missing")
                )
            )
            .scalars()
            .all()
        )
    assert len(tickets) == 1
    assert tickets[0].priority.value == "medium"

    urgent = await client.post(
        "/api/v1/support/tickets",
        json={**body, "subject": "Please hurry", "priority": "urgent"},
        headers=headers,
    )
    assert urgent.json()["priority"] == "high"  # customers cannot self-assign "urgent"

    listing = (await client.get("/api/v1/support/tickets", headers=headers)).json()["items"]
    assert {t["subject"] for t in listing} == {"Remote missing", "Please hurry"}


async def test_ticket_description_never_stores_card_numbers(
    container: AppContainer, client: httpx2.AsyncClient, seeded: Creds, login: Login
) -> None:
    headers = await login(seeded, MAYA)
    response = await client.post(
        "/api/v1/support/tickets",
        json={
            "subject": "Payment issue",
            "description": "My card 4111 1111 1111 1111 was charged twice",
        },
        headers=headers,
    )
    assert "4111" not in response.json()["description"]


async def test_daily_ticket_limit(
    client: httpx2.AsyncClient, seeded: Creds, login: Login, container: AppContainer
) -> None:
    headers = await login(seeded, DANIEL)
    limit = container.settings.agent_max_tickets_per_day
    for i in range(limit):
        created = await client.post(
            "/api/v1/support/tickets",
            json={"subject": f"Issue {i}", "description": "Some description here"},
            headers=headers,
        )
        assert created.status_code == 201
    blocked = await client.post(
        "/api/v1/support/tickets",
        json={"subject": "One more", "description": "Some description here"},
        headers=headers,
    )
    assert blocked.status_code == 429


async def test_ticket_access_control_and_staff_updates(
    client: httpx2.AsyncClient, seeded: Creds, login: Login
) -> None:
    maya = await login(seeded, MAYA)
    sofia = await login(seeded, SOFIA)
    agent = await login(seeded, AGENT)
    ticket = (
        await client.post(
            "/api/v1/support/tickets",
            json={"subject": "Question", "description": "Question about my order"},
            headers=maya,
        )
    ).json()
    assert (
        await client.get(f"/api/v1/support/tickets/{ticket['id']}", headers=sofia)
    ).status_code == 404
    assert (
        await client.patch(
            f"/api/v1/support/tickets/{ticket['id']}", json={"status": "resolved"}, headers=maya
        )
    ).status_code == 403
    updated = await client.patch(
        f"/api/v1/support/tickets/{ticket['id']}",
        json={"status": "in_progress", "priority": "high"},
        headers=agent,
    )
    assert updated.status_code == 200
    assert updated.json()["status"] == "in_progress" and updated.json()["priority"] == "high"
    staff_view = (
        await client.get("/api/v1/support/tickets?status=in_progress", headers=agent)
    ).json()["items"]
    assert ticket["id"] in {t["id"] for t in staff_view}


async def test_refund_review_is_restricted_to_managers(
    client: httpx2.AsyncClient, seeded: Creds, login: Login
) -> None:
    sofia = await login(seeded, SOFIA)
    agent = await login(seeded, AGENT)
    manager = await login(seeded, MANAGER)
    own = (await client.get("/api/v1/refunds", headers=sofia)).json()["items"]
    assert {r["refund_number"] for r in own} == {"RFD-100051", "RFD-100052"}
    pending = next(r for r in own if r["refund_number"] == "RFD-100051")
    maya = await login(seeded, MAYA)
    assert (await client.get(f"/api/v1/refunds/{pending['id']}", headers=maya)).status_code == 404

    decision = {"approve": True, "note": "Defective unit confirmed"}
    assert (
        await client.post(f"/api/v1/refunds/{pending['id']}/decision", json=decision, headers=sofia)
    ).status_code == 403
    assert (
        await client.post(f"/api/v1/refunds/{pending['id']}/decision", json=decision, headers=agent)
    ).status_code == 403
    approved = await client.post(
        f"/api/v1/refunds/{pending['id']}/decision", json=decision, headers=manager
    )
    assert approved.status_code == 200 and approved.json()["status"] == "completed"
    again = await client.post(
        f"/api/v1/refunds/{pending['id']}/decision", json=decision, headers=manager
    )
    assert again.status_code == 409


async def test_refund_rejection(client: httpx2.AsyncClient, seeded: Creds, login: Login) -> None:
    manager = await login(seeded, MANAGER)
    pending = (await client.get("/api/v1/refunds?status=pending_review", headers=manager)).json()[
        "items"
    ]
    rejected = await client.post(
        f"/api/v1/refunds/{pending[0]['id']}/decision",
        json={"approve": False, "note": "Outside policy"},
        headers=manager,
    )
    assert rejected.json()["status"] == "rejected"


@pytest.mark.security
@pytest.mark.parametrize("approve", [1, 0, "true", "yes", "false", None])
async def test_refund_decision_requires_a_json_boolean(
    client: httpx2.AsyncClient, seeded: Creds, login: Login, approve: object
) -> None:
    # Found by API fuzzing: lax coercion turned 0 into "reject" and 1 into "approve".
    manager = await login(seeded, MANAGER)
    pending = (await client.get("/api/v1/refunds?status=pending_review", headers=manager)).json()[
        "items"
    ][0]
    response = await client.post(
        f"/api/v1/refunds/{pending['id']}/decision", json={"approve": approve}, headers=manager
    )
    assert response.status_code == 422
    assert response.json()["errors"][0]["loc"] == ["body", "approve"]
    unchanged = await client.get(f"/api/v1/refunds/{pending['id']}", headers=manager)
    assert unchanged.json()["status"] == "pending_review"
