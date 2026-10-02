"""HTTP-level security regression tests."""

from __future__ import annotations

import uuid
from collections.abc import AsyncIterator, Callable
from datetime import UTC, datetime, timedelta
from typing import Any

import httpx2
import jwt
import pytest
from sqlalchemy import select, update

from aegis.bootstrap import AppContainer
from aegis.main import create_app
from aegis.models import Conversation, SupportTicket, User
from aegis.services.auth import AuthService
from tests.conftest import ADMIN, AGENT, MAYA, SOFIA, build_container, make_settings

pytestmark = pytest.mark.security

Creds = dict[str, dict[str, str]]
Login = Callable[[Creds, str], Any]
SECURITY_HEADERS = {
    "x-content-type-options": "nosniff",
    "x-frame-options": "DENY",
    "referrer-policy": "no-referrer",
    "cache-control": "no-store",
}


def assert_security_headers(response: httpx2.Response) -> None:
    for header, value in SECURITY_HEADERS.items():
        assert response.headers.get(header) == value, header
    assert "default-src 'none'" in response.headers["content-security-policy"]
    assert "server" not in response.headers
    assert response.headers.get("x-request-id")


async def test_security_headers_on_success_and_error_responses(
    client: httpx2.AsyncClient, seeded: Creds
) -> None:
    responses = [
        await client.get("/health/live"),
        await client.get("/api/v1/auth/me"),
        await client.get("/does-not-exist"),
        await client.post("/api/v1/auth/login", json={"email": "not-an-email", "password": "x"}),
    ]
    assert [r.status_code for r in responses] == [200, 401, 404, 422]
    for response in responses:
        assert_security_headers(response)
    assert all(
        r.headers["content-type"].startswith("application/problem+json") for r in responses[1:]
    )


async def test_request_id_is_sanitised(client: httpx2.AsyncClient) -> None:
    good = await client.get("/health/live", headers={"X-Request-ID": "trace-12345678"})
    assert good.headers["x-request-id"] == "trace-12345678"
    evil = await client.get(
        "/health/live", headers={"X-Request-ID": 'x"; injected=1; ' + "a" * 200}
    )
    assert evil.headers["x-request-id"] != 'x"; injected=1; ' + "a" * 200
    assert len(evil.headers["x-request-id"]) == 32


async def test_oversized_bodies_are_rejected_before_processing(client: httpx2.AsyncClient) -> None:
    big = b'{"email": "a@example.com", "password": "' + b"x" * 70_000 + b'"}'
    declared = await client.post(
        "/api/v1/auth/login", content=big, headers={"Content-Type": "application/json"}
    )
    assert declared.status_code == 413

    async def stream() -> AsyncIterator[bytes]:
        for _ in range(20):
            yield b"x" * 8_192

    chunked = await client.post(
        "/api/v1/auth/login", content=stream(), headers={"Content-Type": "application/json"}
    )
    assert chunked.status_code == 413
    assert_security_headers(chunked)


@pytest.mark.parametrize(
    "content_type",
    ["text/plain", "application/x-www-form-urlencoded", "multipart/form-data; boundary=x", ""],
)
async def test_non_json_bodies_are_rejected(client: httpx2.AsyncClient, content_type: str) -> None:
    response = await client.post(
        "/api/v1/auth/login",
        content=b'{"email":"a@example.com","password":"x"}',
        headers={"Content-Type": content_type},
    )
    assert response.status_code == 415


async def test_unknown_host_header_is_rejected(client: httpx2.AsyncClient) -> None:
    response = await client.get("/health/live", headers={"Host": "evil.example"})
    assert response.status_code == 400


@pytest.mark.parametrize(
    ("method", "path", "allow"),
    [
        # Served by two routes (GET and POST): Starlette alone would advertise only one of them.
        ("PUT", "/api/v1/conversations", "GET, POST"),
        ("DELETE", "/api/v1/support/tickets", "GET, POST"),
        ("GET", "/api/v1/auth/login", "POST"),
    ],
)
async def test_method_not_allowed_lists_every_supported_method(
    client: httpx2.AsyncClient, method: str, path: str, allow: str
) -> None:
    response = await client.request(method, path)
    assert response.status_code == 405
    assert response.headers["allow"] == allow
    assert response.json()["code"] == "http_405"
    assert_security_headers(response)


async def test_cors_only_for_configured_origins() -> None:
    container = await build_container(make_settings(cors_origins="https://app.acme.example"))
    try:
        app = create_app(container.settings, container=container)
        async with httpx2.AsyncClient(
            transport=httpx2.ASGITransport(app=app), base_url="http://testserver"
        ) as client:
            preflight = {
                "Access-Control-Request-Method": "POST",
                "Access-Control-Request-Headers": "authorization",
            }
            allowed = await client.options(
                "/api/v1/auth/login", headers={"Origin": "https://app.acme.example", **preflight}
            )
            denied = await client.options(
                "/api/v1/auth/login", headers={"Origin": "https://evil.example", **preflight}
            )
    finally:
        await container.close()
    assert allowed.headers.get("access-control-allow-origin") == "https://app.acme.example"
    assert "access-control-allow-credentials" not in allowed.headers
    assert "access-control-allow-origin" not in denied.headers


async def test_validation_errors_never_echo_input(client: httpx2.AsyncClient) -> None:
    secret = "Sup3r-Secret-Password!" * 10
    response = await client.post(
        "/api/v1/auth/login", json={"email": "a@example.com", "password": secret}
    )
    assert response.status_code == 422
    assert "Sup3r-Secret" not in response.text
    assert response.json()["errors"][0]["loc"] == ["body", "password"]


async def test_internal_errors_do_not_leak_details(
    client: httpx2.AsyncClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    async def explode(*args: object, **kwargs: object) -> None:
        raise RuntimeError(
            "connection to postgres at 10.20.4.15:5432 failed: password authentication failed"
        )

    monkeypatch.setattr(AuthService, "login", explode)
    response = await client.post(
        "/api/v1/auth/login", json={"email": "a@example.com", "password": "whatever-123"}
    )
    assert response.status_code == 500
    assert "10.20.4.15" not in response.text and "postgres" not in response.text
    assert response.json()["detail"] == "An unexpected error occurred. Please try again later."
    assert response.json()["request_id"]
    assert_security_headers(response)


def _forge(
    claims: dict[str, Any],
    key: str = "attacker-key-0123456789-abcdefghijklmnopqrstuvwxyz",
    alg: str = "HS256",
) -> str:
    return jwt.encode(claims, key, algorithm=alg)


async def test_forged_and_malformed_tokens_are_rejected(
    client: httpx2.AsyncClient, container: AppContainer, seeded: Creds
) -> None:
    async with container.sessionmaker() as session:
        admin = (await session.execute(select(User).where(User.email == ADMIN))).scalar_one()
    now = datetime.now(UTC)
    claims = {
        "iss": "aegis-support",
        "aud": "aegis-support-api",
        "sub": str(admin.id),
        "sid": str(uuid.uuid4()),
        "role": "admin",
        "typ": "access",
        "jti": "x",
        "iat": now,
        "nbf": now,
        "exp": now + timedelta(minutes=5),
    }
    real_secret = container.settings.jwt_secret.get_secret_value()
    tokens = [
        _forge(claims),  # wrong key
        _forge(claims, key=real_secret),  # right key but the session does not exist
        "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0."
        + jwt.utils.base64url_encode(b'{"sub":"x","role":"admin"}').decode()
        + ".",
        "not.a.jwt",
        "Bearer",
    ]
    for token in tokens:
        response = await client.get(
            "/api/v1/admin/users", headers={"Authorization": f"Bearer {token}"}
        )
        assert response.status_code == 401, token
        assert response.headers["www-authenticate"].startswith("Bearer")
    basic = await client.get(
        "/api/v1/admin/users", headers={"Authorization": "Basic YWRtaW46YWRtaW4="}
    )
    assert basic.status_code == 401


async def test_role_changes_apply_to_existing_tokens(
    client: httpx2.AsyncClient, container: AppContainer, seeded: Creds, login: Login
) -> None:
    headers = await login(seeded, ADMIN)
    assert (await client.get("/api/v1/admin/users", headers=headers)).status_code == 200
    async with container.sessionmaker() as session:
        await session.execute(update(User).where(User.email == ADMIN).values(role="support_agent"))
        await session.commit()
    assert (await client.get("/api/v1/admin/users", headers=headers)).status_code == 403


async def test_idor_matrix_between_customers(
    client: httpx2.AsyncClient, container: AppContainer, seeded: Creds, login: Login
) -> None:
    maya = await login(seeded, MAYA)
    sofia = await login(seeded, SOFIA)
    conversation = (await client.post("/api/v1/conversations", json={}, headers=sofia)).json()["id"]
    turn = (
        await client.post(
            f"/api/v1/conversations/{conversation}/messages",
            json={"content": "Cancel order ORD-100251"},
            headers=sofia,
        )
    ).json()
    assert turn["reply"] is not None
    async with container.sessionmaker() as session:
        ticket = (
            await session.execute(
                select(SupportTicket).where(SupportTicket.ticket_number == "TCK-10000123")
            )
        ).scalar_one()
    sofia_refunds = (await client.get("/api/v1/refunds", headers=sofia)).json()["items"]
    fake_action = uuid.uuid4()
    probes = [
        ("GET", f"/api/v1/conversations/{conversation}"),
        ("GET", f"/api/v1/conversations/{conversation}/messages"),
        ("POST", f"/api/v1/conversations/{conversation}/messages"),
        ("GET", f"/api/v1/conversations/{conversation}/actions"),
        ("POST", f"/api/v1/conversations/{conversation}/actions/{fake_action}/confirm"),
        ("POST", f"/api/v1/conversations/{conversation}/close"),
        ("GET", f"/api/v1/support/tickets/{ticket.id}"),
        ("GET", f"/api/v1/refunds/{sofia_refunds[0]['id']}"),
        ("GET", "/api/v1/orders/ORD-100251"),
    ]
    for method, path in probes:
        body: dict[str, Any] | None = (
            {"content": "hi"} if method == "POST" and path.endswith("messages") else None
        )
        response = await client.request(method, path, headers=maya, json=body)
        assert response.status_code == 404, (method, path, response.status_code)


async def test_privilege_escalation_is_blocked(
    client: httpx2.AsyncClient, seeded: Creds, login: Login
) -> None:
    customer = await login(seeded, MAYA)
    agent = await login(seeded, AGENT)
    rid = uuid.uuid4()
    customer_forbidden = [
        ("GET", "/api/v1/admin/users"),
        ("GET", "/api/v1/admin/audit-events"),
        ("GET", "/api/v1/admin/llm-usage"),
        ("GET", "/api/v1/admin/knowledge-base/documents"),
        ("GET", "/api/v1/agent-desk/queue"),
        ("POST", f"/api/v1/refunds/{rid}/decision"),
        ("PATCH", f"/api/v1/support/tickets/{rid}"),
    ]
    for method, path in customer_forbidden:
        payload: dict[str, Any] | None = (
            {"approve": True} if "decision" in path else ({} if method == "PATCH" else None)
        )
        response = await client.request(method, path, headers=customer, json=payload)
        assert response.status_code == 403, (method, path)
    agent_forbidden = [
        ("GET", "/api/v1/admin/users"),
        ("POST", f"/api/v1/refunds/{rid}/decision"),
        ("POST", "/api/v1/conversations"),
    ]
    for method, path in agent_forbidden:
        agent_payload: dict[str, Any] | None = (
            {"approve": True} if "decision" in path else ({} if method == "POST" else None)
        )
        response = await client.request(method, path, headers=agent, json=agent_payload)
        assert response.status_code == 403, (method, path)


async def test_staff_cannot_confirm_customer_actions(
    client: httpx2.AsyncClient, container: AppContainer, seeded: Creds, login: Login
) -> None:
    customer = await login(seeded, MAYA)
    agent = await login(seeded, AGENT)
    conversation = (await client.post("/api/v1/conversations", json={}, headers=customer)).json()[
        "id"
    ]
    turn = (
        await client.post(
            f"/api/v1/conversations/{conversation}/messages",
            json={"content": "Cancel my order ORD-100233"},
            headers=customer,
        )
    ).json()
    [action] = turn["pending_actions"]
    confirm = await client.post(
        f"/api/v1/conversations/{conversation}/actions/{action['id']}/confirm", headers=agent
    )
    assert confirm.status_code == 403


async def test_llm_endpoint_rate_limit(tmp_path: Any) -> None:
    from tests.conftest import seed

    container = await build_container(make_settings(rl_llm_per_user_per_minute=2))
    try:
        credentials = await seed(container, tmp_path, with_kb=False)
        app = create_app(container.settings, container=container)
        async with httpx2.AsyncClient(
            transport=httpx2.ASGITransport(app=app), base_url="http://testserver"
        ) as client:
            token = (
                await client.post(
                    "/api/v1/auth/login",
                    json={"email": MAYA, "password": credentials[MAYA]["password"]},
                )
            ).json()["access_token"]
            headers = {"Authorization": f"Bearer {token}"}
            conversation = (
                await client.post("/api/v1/conversations", json={}, headers=headers)
            ).json()["id"]
            statuses = [
                (
                    await client.post(
                        f"/api/v1/conversations/{conversation}/messages",
                        json={"content": "Where is ORD-100232?"},
                        headers=headers,
                    )
                ).status_code
                for _ in range(3)
            ]
    finally:
        await container.close()
    assert statuses == [200, 200, 429]


async def test_api_is_rate_limited_per_client_ip_even_without_a_valid_token() -> None:
    """Token guessing and anonymous floods are throttled before authentication runs."""
    container = await build_container(make_settings(rl_api_per_ip_per_minute=3))
    try:
        app = create_app(container.settings, container=container)
        transport = httpx2.ASGITransport(app=app, client=("198.51.100.7", 40000))
        async with httpx2.AsyncClient(transport=transport, base_url="http://testserver") as http:
            bad = {"Authorization": "Bearer not-a-real-token"}
            statuses = [
                (await http.get("/api/v1/auth/me", headers=bad)).status_code for _ in range(4)
            ]
            limited = await http.get("/api/v1/auth/me", headers=bad)
            probe = await http.get("/health/live")
        other = httpx2.ASGITransport(app=app, client=("198.51.100.8", 40000))
        async with httpx2.AsyncClient(transport=other, base_url="http://testserver") as http:
            fresh = await http.get("/api/v1/auth/me", headers=bad)
    finally:
        await container.close()
    assert statuses == [401, 401, 401, 429]
    assert limited.headers.get("retry-after")
    assert limited.headers["content-type"].startswith("application/problem+json")
    assert probe.status_code == 200  # health probes are outside the versioned API
    assert fresh.status_code == 401  # the limit is per client address


def test_openapi_documents_problem_responses() -> None:
    app = create_app(make_settings(api_docs_enabled=True))
    operation = app.openapi()["paths"]["/api/v1/conversations"]["post"]
    for status in ("401", "403", "422", "429", "500"):
        assert "application/problem+json" in operation["responses"][status]["content"], status


async def test_metrics_require_the_configured_token() -> None:
    container = await build_container(
        make_settings(metrics_token="metrics-secret-token-0123456789")
    )
    try:
        app = create_app(container.settings, container=container)
        async with httpx2.AsyncClient(
            transport=httpx2.ASGITransport(app=app), base_url="http://testserver"
        ) as client:
            anonymous = await client.get("/metrics")
            wrong = await client.get("/metrics", headers={"Authorization": "Bearer nope"})
            right = await client.get(
                "/metrics", headers={"Authorization": "Bearer metrics-secret-token-0123456789"}
            )
    finally:
        await container.close()
    assert anonymous.status_code == wrong.status_code == 401
    assert right.status_code == 200


async def test_docs_can_be_disabled() -> None:
    container = await build_container(make_settings(api_docs_enabled=False))
    try:
        app = create_app(container.settings, container=container)
        async with httpx2.AsyncClient(
            transport=httpx2.ASGITransport(app=app), base_url="http://testserver"
        ) as client:
            assert (await client.get("/docs")).status_code == 404
            assert (await client.get("/openapi.json")).status_code == 404
    finally:
        await container.close()


async def test_message_content_is_encrypted_at_rest(
    client: httpx2.AsyncClient, container: AppContainer, seeded: Creds, login: Login
) -> None:
    headers = await login(seeded, MAYA)
    conversation = (await client.post("/api/v1/conversations", json={}, headers=headers)).json()[
        "id"
    ]
    await client.post(
        f"/api/v1/conversations/{conversation}/messages",
        json={"content": "My unique phrase is violet-marmalade-kingdom, where is ORD-100232?"},
        headers=headers,
    )
    async with container.engine.connect() as connection:
        from sqlalchemy import text

        raw: list[str] = list(
            (await connection.execute(text("SELECT content FROM conversation_messages"))).scalars()
        )
        phone: str = (
            await connection.execute(text("SELECT phone FROM customers LIMIT 1"))
        ).scalar_one()
    assert raw and all("violet-marmalade-kingdom" not in value for value in raw)
    assert all(value.startswith("gAAAA") for value in raw)  # Fernet tokens
    assert "555" not in phone
    async with container.sessionmaker() as session:
        assert (await session.execute(select(Conversation))).scalars().first() is not None
