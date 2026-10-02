"""Data-subject rights: export, erasure request, erasure, retention period."""

from __future__ import annotations

import uuid
from collections.abc import Callable
from datetime import timedelta
from pathlib import Path
from typing import Any

import httpx2
from sqlalchemy import select, text, update

from aegis.bootstrap import AppContainer, RequestServices
from aegis.core.time import utc_now
from aegis.domain.enums import SenderType
from aegis.main import create_app
from aegis.models import AuditEvent, Conversation, Customer, Message, Order, User
from aegis.services.privacy import ERASED_TEXT, EXPIRED_TEXT
from tests.conftest import (
    ADMIN,
    AGENT,
    MANAGER,
    MAYA,
    build_container,
    make_settings,
    principal_for,
    seed,
)

Creds = dict[str, dict[str, str]]
Login = Callable[[Creds, str], Any]
NOAH = "noah.williams@example.com"  # one delivered order, nothing in progress: erasable
CARD = "4111 1111 1111 1111"


async def start_conversation(
    client: httpx2.AsyncClient, headers: dict[str, str], message: str, *, subject: str = "Help"
) -> str:
    conversation = await client.post(
        "/api/v1/conversations", json={"subject": subject}, headers=headers
    )
    conversation_id = str(conversation.json()["id"])
    sent = await client.post(
        f"/api/v1/conversations/{conversation_id}/messages",
        json={"content": message},
        headers=headers,
    )
    assert sent.status_code == 200, sent.text
    return conversation_id


async def customer_id_of(container: AppContainer, email: str) -> uuid.UUID:
    async with container.sessionmaker() as session:
        return (
            await session.execute(select(Customer.id).where(Customer.email == email))
        ).scalar_one()


async def test_customers_export_everything_about_themselves(
    client: httpx2.AsyncClient, seeded: Creds, login: Login
) -> None:
    maya = await login(seeded, MAYA)
    await start_conversation(client, maya, "Where is my order ORD-100232?")
    response = await client.get("/api/v1/privacy/export", headers=maya)
    assert response.status_code == 200
    assert response.headers["content-disposition"].startswith("attachment")
    export = response.json()
    assert export["customer"]["email"] == MAYA
    assert export["customer"]["phone"].startswith("+1 555")  # decrypted for its owner
    assert {o["order_number"] for o in export["orders"]} == {
        "ORD-100231",
        "ORD-100232",
        "ORD-100233",
    }
    messages = export["conversations"][0]["messages"]
    assert [m["sender_type"] for m in messages] == ["customer", "assistant"]
    assert "meta" not in messages[0]  # internal classifier/guard data stays internal
    assert export["accounts"][0]["two_factor_enabled"] is False
    # Nobody else's data: another customer's order numbers are absent.
    assert "ORD-100241" not in response.text


async def test_staff_cannot_export_and_exports_are_rate_limited(tmp_path: Path) -> None:
    container = await build_container(make_settings(rl_privacy_export_per_day=2))
    try:
        creds = await seed(container, tmp_path, with_kb=False)
        app = create_app(container.settings, container=container)
        async with httpx2.AsyncClient(
            transport=httpx2.ASGITransport(app=app), base_url="http://testserver"
        ) as client:

            async def token(email: str) -> dict[str, str]:
                response = await client.post(
                    "/api/v1/auth/login",
                    json={"email": email, "password": creds[email]["password"]},
                )
                return {"Authorization": f"Bearer {response.json()['access_token']}"}

            agent = await token(AGENT)
            assert (await client.get("/api/v1/privacy/export", headers=agent)).status_code == 403
            maya = await token(MAYA)
            statuses = [
                (await client.get("/api/v1/privacy/export", headers=maya)).status_code
                for _ in range(3)
            ]
            assert statuses == [200, 200, 429]
    finally:
        await container.close()


async def test_erasure_request_opens_one_ticket_per_day(
    client: httpx2.AsyncClient, seeded: Creds, login: Login
) -> None:
    maya = await login(seeded, MAYA)
    first = await client.post("/api/v1/privacy/erasure-request", headers=maya)
    again = await client.post("/api/v1/privacy/erasure-request", headers=maya)
    assert first.status_code == again.status_code == 202
    assert first.json()["ticket_number"] == again.json()["ticket_number"]
    tickets = (await client.get("/api/v1/support/tickets", headers=maya)).json()["items"]
    privacy = [t for t in tickets if t["category"] == "privacy"]
    assert len(privacy) == 1


async def test_erasure_is_admin_only_confirmed_and_waits_for_open_work(
    client: httpx2.AsyncClient, seeded: Creds, login: Login, container: AppContainer
) -> None:
    admin = await login(seeded, ADMIN)
    manager = await login(seeded, MANAGER)
    maya_id = await customer_id_of(container, MAYA)
    url = f"/api/v1/admin/customers/{maya_id}/erase"
    assert (
        await client.post(url, json={"customer_number": "CUS-10001"}, headers=manager)
    ).status_code == 403
    wrong = await client.post(url, json={"customer_number": "CUS-99999"}, headers=admin)
    assert wrong.status_code == 422
    blocked = await client.post(url, json={"customer_number": "CUS-10001"}, headers=admin)
    assert blocked.status_code == 409  # Maya has orders in progress
    assert "orders_in_progress" in blocked.text


async def test_erasure_anonymises_the_customer_irreversibly(
    client: httpx2.AsyncClient, seeded: Creds, login: Login, container: AppContainer
) -> None:
    noah = await login(seeded, NOAH)
    conversation_id = await start_conversation(
        client, noah, "My address changed to 55 Cedar Blvd, please update it", subject="Address"
    )
    admin = await login(seeded, ADMIN)
    noah_id = await customer_id_of(container, NOAH)
    report = await client.post(
        f"/api/v1/admin/customers/{noah_id}/erase",
        json={"customer_number": "cus-10006"},
        headers=admin,
    )
    assert report.status_code == 200, report.text
    counts = report.json()["counts"]
    assert counts["users"] == 1 and counts["messages"] >= 2 and counts["orders"] == 1

    # The login is gone - even with the right password.
    relogin = await client.post(
        "/api/v1/auth/login", json={"email": NOAH, "password": seeded[NOAH]["password"]}
    )
    assert relogin.status_code == 401
    assert (await client.get("/api/v1/auth/me", headers=noah)).status_code == 401

    async with container.sessionmaker() as session:
        customer = await session.get(Customer, noah_id)
        assert customer is not None and customer.erased_at is not None
        assert (
            customer.email.endswith("@erased.invalid") and customer.full_name == "Erased customer"
        )
        assert customer.phone is None and customer.address is None
        user = (await session.execute(select(User).where(User.customer_id == noah_id))).scalar_one()
        assert user.email.endswith("@erased.invalid") and not user.is_active
        contents = {
            m.content
            for m in (
                await session.execute(
                    select(Message).where(Message.conversation_id == uuid.UUID(conversation_id))
                )
            ).scalars()
        }
        assert contents == {ERASED_TEXT}
        conversation = await session.get(Conversation, uuid.UUID(conversation_id))
        assert conversation is not None and conversation.subject is None
        order = (
            await session.execute(select(Order).where(Order.customer_id == noah_id))
        ).scalar_one()
        assert order.shipping_address is None and order.total_cents > 0  # the record remains
        actions = set((await session.execute(select(AuditEvent.action))).scalars())
    assert "privacy.erase" in actions
    again = await client.post(
        f"/api/v1/admin/customers/{noah_id}/erase",
        json={"customer_number": "CUS-10006"},
        headers=admin,
    )
    assert again.status_code == 409


async def test_retention_period_erases_old_finished_conversations(tmp_path: Path) -> None:
    container = await build_container(make_settings(conversation_retention_days=30))
    try:
        await seed(container, tmp_path, with_kb=False)
        maya = await principal_for(container, MAYA)
        async with container.sessionmaker() as session:
            services = RequestServices(container, session)
            old = await services.conversations.create(maya, subject="Old question")
            recent = await services.conversations.create(maya, subject="Recent question")
            for conversation in (old, recent):
                await services.conversations.append(
                    conversation,
                    sender_type=SenderType.CUSTOMER,
                    content="my phone is +1 555 0101 234",
                    sender_user_id=maya.user_id,
                )
            await services.conversations.commit()
            await session.execute(
                update(Conversation)
                .where(Conversation.id.in_([old.id, recent.id]))
                .values(status="closed")
            )
            await session.execute(
                update(Conversation)
                .where(Conversation.id == old.id)
                .values(last_message_at=utc_now() - timedelta(days=60))
            )
            await session.commit()
            old_id, recent_id = old.id, recent.id
        async with container.sessionmaker() as session:
            stats = await RequestServices(container, session).maintenance.run()
        assert stats["expired_conversations"] == 1
        async with container.sessionmaker() as session:
            old_texts = {
                m.content
                for m in (
                    await session.execute(select(Message).where(Message.conversation_id == old_id))
                ).scalars()
            }
            recent_texts = {
                m.content
                for m in (
                    await session.execute(
                        select(Message).where(Message.conversation_id == recent_id)
                    )
                ).scalars()
            }
        assert old_texts == {EXPIRED_TEXT}
        assert recent_texts == {"my phone is +1 555 0101 234"}
    finally:
        await container.close()


async def test_conversation_subjects_never_store_card_numbers(
    client: httpx2.AsyncClient, seeded: Creds, login: Login, container: AppContainer
) -> None:
    maya = await login(seeded, MAYA)
    created = await client.post(
        "/api/v1/conversations", json={"subject": f"Charged twice on card {CARD}"}, headers=maya
    )
    assert created.status_code == 201
    async with container.engine.connect() as connection:
        stored: str = (
            await connection.execute(
                text("SELECT subject FROM conversations WHERE subject IS NOT NULL")
            )
        ).scalar_one()
    assert CARD not in stored and "4111" not in stored
