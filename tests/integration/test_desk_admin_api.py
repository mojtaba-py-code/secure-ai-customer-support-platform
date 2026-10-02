from __future__ import annotations

from collections.abc import Callable
from pathlib import Path
from typing import Any

import httpx2
from sqlalchemy import select, text

from aegis.bootstrap import AppContainer
from aegis.domain.enums import KnowledgeVisibility
from aegis.models import AuditEvent, User
from tests.conftest import ADMIN, AGENT, AGENT2, MANAGER, MAYA, SOFIA

Creds = dict[str, dict[str, str]]
Login = Callable[[Creds, str], Any]
MALICIOUS_DOC = Path(__file__).resolve().parents[1] / "fixtures" / "malicious-kb.md"


async def _escalated_conversation(client: httpx2.AsyncClient, headers: dict[str, str]) -> str:
    conversation = (await client.post("/api/v1/conversations", json={}, headers=headers)).json()[
        "id"
    ]
    turn = (
        await client.post(
            f"/api/v1/conversations/{conversation}/messages",
            json={"content": "I want to talk to a human agent please"},
            headers=headers,
        )
    ).json()
    assert turn["escalated"], turn
    return str(conversation)


async def test_human_handoff_workflow(
    client: httpx2.AsyncClient, seeded: Creds, login: Login
) -> None:
    customer = await login(seeded, MAYA)
    agent = await login(seeded, AGENT)
    other_agent = await login(seeded, AGENT2)
    conversation = await _escalated_conversation(client, customer)

    queue = (await client.get("/api/v1/agent-desk/queue", headers=agent)).json()
    item = next(q for q in queue if q["id"] == conversation)
    assert item["escalation_reason"] == "customer_request" and item["status"] == "awaiting_agent"

    assert (
        await client.post(
            f"/api/v1/agent-desk/conversations/{conversation}/messages",
            json={"content": "Hi"},
            headers=agent,
        )
    ).status_code == 409  # must claim first
    claimed = await client.post(
        f"/api/v1/agent-desk/conversations/{conversation}/claim", headers=agent
    )
    assert claimed.json()["status"] == "agent_assigned"
    assert (
        await client.post(
            f"/api/v1/agent-desk/conversations/{conversation}/claim", headers=other_agent
        )
    ).status_code == 403
    assert (
        await client.post(
            f"/api/v1/agent-desk/conversations/{conversation}/messages",
            json={"content": "Hi"},
            headers=other_agent,
        )
    ).status_code == 403

    replied = await client.post(
        f"/api/v1/agent-desk/conversations/{conversation}/messages",
        json={"content": "Hello Maya, I'm Sam from support. How can I help?"},
        headers=agent,
    )
    assert replied.status_code == 200 and replied.json()["sender_type"] == "agent"
    history = (await client.get(f"/api/v1/conversations/{conversation}", headers=customer)).json()[
        "messages"
    ]
    assert history[-1]["sender_type"] == "agent"

    detail = (
        await client.get(f"/api/v1/agent-desk/conversations/{conversation}", headers=agent)
    ).json()
    assert detail["escalation_reason"] == "customer_request"
    assert any(m["meta"].get("escalated") for m in detail["messages"])

    resolved = await client.post(
        f"/api/v1/agent-desk/conversations/{conversation}/resolve",
        json={"return_to_ai": True},
        headers=agent,
    )
    assert resolved.json()["status"] == "active"
    turn = (
        await client.post(
            f"/api/v1/conversations/{conversation}/messages",
            json={"content": "Where is ORD-100232?"},
            headers=customer,
        )
    ).json()
    assert turn["reply"] is not None and "ORD-100232" in turn["reply"]["content"]


async def test_manager_assignment_and_customer_restrictions(
    client: httpx2.AsyncClient, seeded: Creds, login: Login, container: AppContainer
) -> None:
    customer = await login(seeded, MAYA)
    agent = await login(seeded, AGENT)
    manager = await login(seeded, MANAGER)
    conversation = await _escalated_conversation(client, customer)
    async with container.sessionmaker() as session:
        agent_id = (await session.execute(select(User.id).where(User.email == AGENT2))).scalar_one()
        customer_id = (
            await session.execute(select(User.id).where(User.email == SOFIA))
        ).scalar_one()
    assert (
        await client.post(
            f"/api/v1/agent-desk/conversations/{conversation}/assign",
            json={"agent_user_id": str(agent_id)},
            headers=agent,
        )
    ).status_code == 403
    assert (
        await client.post(
            f"/api/v1/agent-desk/conversations/{conversation}/assign",
            json={"agent_user_id": str(customer_id)},
            headers=manager,
        )
    ).status_code == 422
    assigned = await client.post(
        f"/api/v1/agent-desk/conversations/{conversation}/assign",
        json={"agent_user_id": str(agent_id)},
        headers=manager,
    )
    assert assigned.status_code == 200 and assigned.json()["assigned_agent_id"] == str(agent_id)
    for path in ("/api/v1/agent-desk/queue", f"/api/v1/agent-desk/conversations/{conversation}"):
        assert (await client.get(path, headers=customer)).status_code == 403


async def test_staff_user_management(
    client: httpx2.AsyncClient, seeded: Creds, login: Login, container: AppContainer
) -> None:
    admin = await login(seeded, ADMIN)
    manager = await login(seeded, MANAGER)
    new_user = {
        "email": "new.agent@acme.example",
        "display_name": "New Agent",
        "role": "support_agent",
        "password": "copper-kettle-orbit-95",
    }
    assert (
        await client.post("/api/v1/admin/users", json=new_user, headers=manager)
    ).status_code == 403
    weak = await client.post(
        "/api/v1/admin/users", json={**new_user, "password": "password123"}, headers=admin
    )
    assert weak.status_code == 422
    customer_role = await client.post(
        "/api/v1/admin/users", json={**new_user, "role": "customer"}, headers=admin
    )
    assert customer_role.status_code == 422
    created = await client.post("/api/v1/admin/users", json=new_user, headers=admin)
    assert created.status_code == 201
    assert "password" not in created.json() and "password_hash" not in created.json()
    duplicate = await client.post("/api/v1/admin/users", json=new_user, headers=admin)
    assert duplicate.status_code == 409

    user_id = created.json()["id"]
    session = await client.post(
        "/api/v1/auth/login", json={"email": new_user["email"], "password": new_user["password"]}
    )
    new_headers = {"Authorization": f"Bearer {session.json()['access_token']}"}
    promoted = await client.patch(
        f"/api/v1/admin/users/{user_id}", json={"role": "support_manager"}, headers=admin
    )
    assert promoted.json()["role"] == "support_manager"
    # the new role applies to existing tokens immediately (role is read from the database)
    assert (
        await client.get("/api/v1/refunds?status=pending_review", headers=new_headers)
    ).status_code == 200
    for not_a_boolean in (0, "false", "no"):  # lax coercion would deactivate the account
        coerced = await client.patch(
            f"/api/v1/admin/users/{user_id}", json={"is_active": not_a_boolean}, headers=admin
        )
        assert coerced.status_code == 422, not_a_boolean
    assert (await client.get("/api/v1/auth/me", headers=new_headers)).status_code == 200
    deactivated = await client.patch(
        f"/api/v1/admin/users/{user_id}", json={"is_active": False}, headers=admin
    )
    assert deactivated.json()["is_active"] is False
    assert (await client.get("/api/v1/auth/me", headers=new_headers)).status_code == 401

    async with container.sessionmaker() as db:
        admin_id = (await db.execute(select(User.id).where(User.email == ADMIN))).scalar_one()
    self_demote = await client.patch(
        f"/api/v1/admin/users/{admin_id}", json={"role": "support_agent"}, headers=admin
    )
    assert self_demote.status_code == 409
    users = (await client.get("/api/v1/admin/users?role=admin", headers=admin)).json()["items"]
    assert [u["email"] for u in users] == [ADMIN]
    assert (
        await client.post(f"/api/v1/admin/users/{user_id}/unlock", headers=admin)
    ).status_code == 200
    assert (
        await client.post(f"/api/v1/admin/users/{user_id}/revoke-sessions", headers=admin)
    ).json()["revoked_sessions"] >= 0


async def _upload(
    client: httpx2.AsyncClient,
    headers: dict[str, str],
    name: str,
    content: bytes,
    *,
    visibility: str = "public",
    index_now: bool = True,
    title: str = "Holiday Returns",
) -> httpx2.Response:
    return await client.post(
        f"/api/v1/admin/knowledge-base/documents?index_now={'true' if index_now else 'false'}",
        headers=headers,
        files={"file": (name, content, "text/markdown")},
        data={"title": title, "category": "refund_policy", "visibility": visibility},
    )


async def test_knowledge_base_upload_index_and_archive(
    client: httpx2.AsyncClient, seeded: Creds, login: Login, container: AppContainer
) -> None:
    admin = await login(seeded, ADMIN)
    content = b"# Holiday Returns\n\nOrders delivered in December can be returned until January 31."
    uploaded = await _upload(client, admin, "holiday.md", content)
    assert uploaded.status_code == 202, uploaded.text
    document = uploaded.json()
    assert document["status"] == "indexed" and document["chunk_count"] == 1
    duplicate = await _upload(client, admin, "holiday-copy.md", content)
    assert duplicate.status_code == 409
    chunks = await container.retriever.retrieve(
        "can I return a December delivery in January",
        visibilities=frozenset({KnowledgeVisibility.PUBLIC}),
    )
    assert any(c.document_id == document["id"] for c in chunks)

    listing = (
        await client.get("/api/v1/admin/knowledge-base/documents?status=indexed", headers=admin)
    ).json()["items"]
    assert document["id"] in {d["id"] for d in listing}
    assert (
        await client.delete(
            f"/api/v1/admin/knowledge-base/documents/{document['id']}", headers=admin
        )
    ).status_code == 204
    chunks = await container.retriever.retrieve(
        "can I return a December delivery in January",
        visibilities=frozenset({KnowledgeVisibility.PUBLIC}),
    )
    assert all(c.document_id != document["id"] for c in chunks)


async def test_malicious_document_is_quarantined_until_approved(
    client: httpx2.AsyncClient, seeded: Creds, login: Login, container: AppContainer
) -> None:
    admin = await login(seeded, ADMIN)
    uploaded = await _upload(
        client, admin, "shipping-update.md", MALICIOUS_DOC.read_bytes(), title="Shipping update"
    )
    document = uploaded.json()
    assert document["status"] == "quarantined"
    assert document["injection_score"] > 0.4
    assert await container.vector_store.count() == 0
    approved = await client.post(
        f"/api/v1/admin/knowledge-base/documents/{document['id']}/approve", headers=admin
    )
    assert approved.json()["status"] == "pending"
    indexed = await client.post(
        f"/api/v1/admin/knowledge-base/documents/{document['id']}/reindex", headers=admin
    )
    assert indexed.status_code == 409  # still pending; the worker indexes it
    from aegis.bootstrap import RequestServices

    async with container.sessionmaker() as session:
        await RequestServices(container, session).knowledge.index_pending()
    final = (
        await client.get(f"/api/v1/admin/knowledge-base/documents/{document['id']}", headers=admin)
    ).json()
    assert final["status"] == "indexed"
    chunks = await container.retriever.retrieve(
        "shipping update", visibilities=frozenset({KnowledgeVisibility.PUBLIC})
    )
    assert all("system prompt" not in c.text.lower() for c in chunks)


async def test_upload_validation_and_permissions(
    client: httpx2.AsyncClient, seeded: Creds, login: Login
) -> None:
    admin = await login(seeded, ADMIN)
    agent = await login(seeded, AGENT)
    assert (
        await _upload(client, agent, "a.md", b"# Title\n\nSome useful text for customers.")
    ).status_code == 403
    exe = await client.post(
        "/api/v1/admin/knowledge-base/documents",
        headers=admin,
        files={"file": ("tool.exe", b"MZ\x90\x00binary", "application/octet-stream")},
        data={"title": "Tool", "category": "faq", "visibility": "public"},
    )
    assert exe.status_code == 415
    traversal = await _upload(
        client, admin, "../../etc/passwd.md", b"# Passwd\n\nroot:x:0:0:root:/root:/bin/bash here"
    )
    assert traversal.status_code == 202
    assert traversal.json()["source_filename"] == "passwd.md"
    bad_category = await client.post(
        "/api/v1/admin/knowledge-base/documents",
        headers=admin,
        files={"file": ("x.md", b"# X\n\nSome useful text for customers.", "text/markdown")},
        data={"title": "X", "category": "not_a_category", "visibility": "public"},
    )
    assert bad_category.status_code == 422


async def test_audit_trail_and_usage_endpoints(
    client: httpx2.AsyncClient, seeded: Creds, login: Login, container: AppContainer
) -> None:
    admin = await login(seeded, ADMIN)
    manager = await login(seeded, MANAGER)
    await client.post("/api/v1/auth/login", json={"email": MAYA, "password": "wrong-password-here"})
    events = (
        await client.get(
            "/api/v1/admin/audit-events?action=auth.login&outcome=failure", headers=admin
        )
    ).json()["items"]
    assert events and all(e["action"] == "auth.login" for e in events)
    assert {e["details"].get("reason") for e in events} == {"bad_password"}
    assert all("wrong-password-here" not in str(e) for e in events)  # never the submitted value
    assert (await client.get("/api/v1/admin/audit-events", headers=manager)).status_code == 403
    usage = await client.get("/api/v1/admin/llm-usage?days=7", headers=manager)
    assert usage.status_code == 200 and "lines" in usage.json()
    async with container.sessionmaker() as session:
        count = (await session.execute(select(AuditEvent))).scalars().all()
    assert len(count) >= len(events)


async def test_health_and_metrics(client: httpx2.AsyncClient, container: AppContainer) -> None:
    assert (await client.get("/health/live")).json() == {"status": "ok"}
    ready = await client.get("/health/ready")
    assert ready.status_code == 200 and ready.json()["checks"] == {
        "database": "ok",
        "cache": "ok",
        "vector_store": "ok",
    }
    metrics = await client.get("/metrics")
    assert metrics.status_code == 200 and "aegis_http_requests_total" in metrics.text


async def test_readiness_reports_failures_without_details(
    client: httpx2.AsyncClient, container: AppContainer
) -> None:
    async with container.engine.connect() as connection:
        await connection.execute(text("SELECT 1"))
    await container.vector_store.close()
    ready = await client.get("/health/ready")
    assert ready.status_code == 503
    assert ready.json()["checks"]["vector_store"] == "unavailable"
    assert "Error" not in ready.text and "Traceback" not in ready.text
