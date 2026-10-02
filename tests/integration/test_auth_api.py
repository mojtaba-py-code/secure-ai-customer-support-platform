from __future__ import annotations

from datetime import timedelta
from typing import Any

import httpx2
import pytest
from sqlalchemy import select, update

from aegis.bootstrap import AppContainer
from aegis.core.time import utc_now
from aegis.domain.enums import AuditOutcome
from aegis.models import AuditEvent, PasswordResetToken, User
from tests.conftest import MAYA, build_container, make_settings
from tests.fakes import CapturingEmailSender

Creds = dict[str, dict[str, str]]


async def _login(client: httpx2.AsyncClient, email: str, password: str) -> httpx2.Response:
    return await client.post("/api/v1/auth/login", json={"email": email, "password": password})


async def test_login_me_and_generic_failures(client: httpx2.AsyncClient, seeded: Creds) -> None:
    ok = await _login(client, MAYA, seeded[MAYA]["password"])
    assert ok.status_code == 200
    tokens = ok.json()
    assert tokens["token_type"] == "bearer" and 0 < tokens["expires_in"] <= 900
    me = await client.get(
        "/api/v1/auth/me", headers={"Authorization": f"Bearer {tokens['access_token']}"}
    )
    assert me.status_code == 200
    assert me.json()["role"] == "customer"
    assert "message:send" in me.json()["permissions"]

    wrong = await _login(client, MAYA, "definitely-wrong-password")
    unknown = await _login(client, "nobody@example.com", "definitely-wrong-password")
    assert wrong.status_code == unknown.status_code == 401
    assert wrong.json()["detail"] == unknown.json()["detail"] == "Invalid email or password."
    assert wrong.headers["www-authenticate"].startswith("Bearer")


async def test_email_is_case_insensitive(client: httpx2.AsyncClient, seeded: Creds) -> None:
    response = await _login(client, MAYA.upper(), seeded[MAYA]["password"])
    assert response.status_code == 200


async def test_account_lockout_after_repeated_failures(
    container: AppContainer, client: httpx2.AsyncClient, seeded: Creds
) -> None:
    for _ in range(container.settings.login_max_failed_attempts):
        assert (await _login(client, MAYA, "wrong-password-attempt")).status_code == 401
    # Even the correct password is refused while the account is locked (same generic message).
    locked = await _login(client, MAYA, seeded[MAYA]["password"])
    assert locked.status_code == 401
    async with container.sessionmaker() as session:
        user = (await session.execute(select(User).where(User.email == MAYA))).scalar_one()
        assert user.locked_until is not None
        user.locked_until = utc_now() - timedelta(seconds=1)
        await session.commit()
    assert (await _login(client, MAYA, seeded[MAYA]["password"])).status_code == 200
    async with container.sessionmaker() as session:
        events = (
            (await session.execute(select(AuditEvent).where(AuditEvent.action == "auth.login")))
            .scalars()
            .all()
        )
    reasons = {e.details.get("reason") for e in events if e.outcome is AuditOutcome.FAILURE}
    assert {"bad_password", "account_locked"} <= reasons


async def test_login_rate_limit_per_ip() -> None:
    container = await build_container(make_settings(rl_login_per_ip_per_minute=3))
    try:
        from aegis.main import create_app

        app = create_app(container.settings, container=container)
        async with httpx2.AsyncClient(
            transport=httpx2.ASGITransport(app=app), base_url="http://testserver"
        ) as client:
            statuses = [
                (await _login(client, f"user{i}@example.com", "some-password-1")).status_code
                for i in range(5)
            ]
            limited = await _login(client, "x@example.com", "some-password-1")
    finally:
        await container.close()
    assert statuses[:3] == [401, 401, 401]
    assert statuses[3:] == [429, 429]
    assert int(limited.headers["retry-after"]) >= 1
    assert limited.json()["code"] == "rate_limited"


async def test_refresh_rotation_and_reuse_detection(
    client: httpx2.AsyncClient, seeded: Creds
) -> None:
    first = (await _login(client, MAYA, seeded[MAYA]["password"])).json()
    rotated = await client.post(
        "/api/v1/auth/refresh", json={"refresh_token": first["refresh_token"]}
    )
    assert rotated.status_code == 200
    second = rotated.json()
    assert second["refresh_token"] != first["refresh_token"]
    # Re-using the spent token = theft: the whole session is revoked, including the new tokens.
    reuse = await client.post(
        "/api/v1/auth/refresh", json={"refresh_token": first["refresh_token"]}
    )
    assert reuse.status_code == 401
    me = await client.get(
        "/api/v1/auth/me", headers={"Authorization": f"Bearer {second['access_token']}"}
    )
    assert me.status_code == 401
    assert (
        await client.post("/api/v1/auth/refresh", json={"refresh_token": second["refresh_token"]})
    ).status_code == 401


@pytest.mark.parametrize("token", ["x" * 30, "invalid token with spaces!!", "a" * 300])
async def test_malformed_refresh_tokens(
    client: httpx2.AsyncClient, seeded: Creds, token: str
) -> None:
    response = await client.post("/api/v1/auth/refresh", json={"refresh_token": token})
    assert response.status_code in (401, 422)


async def test_logout_revokes_immediately(client: httpx2.AsyncClient, seeded: Creds) -> None:
    tokens = (await _login(client, MAYA, seeded[MAYA]["password"])).json()
    headers = {"Authorization": f"Bearer {tokens['access_token']}"}
    assert (await client.post("/api/v1/auth/logout", headers=headers)).status_code == 204
    assert (await client.get("/api/v1/auth/me", headers=headers)).status_code == 401
    assert (
        await client.post("/api/v1/auth/refresh", json={"refresh_token": tokens["refresh_token"]})
    ).status_code == 401


async def test_logout_all_revokes_every_session(client: httpx2.AsyncClient, seeded: Creds) -> None:
    a = (await _login(client, MAYA, seeded[MAYA]["password"])).json()
    b = (await _login(client, MAYA, seeded[MAYA]["password"])).json()
    response = await client.post(
        "/api/v1/auth/logout-all", headers={"Authorization": f"Bearer {a['access_token']}"}
    )
    assert response.json()["revoked_sessions"] == 2
    assert (
        await client.get(
            "/api/v1/auth/me", headers={"Authorization": f"Bearer {b['access_token']}"}
        )
    ).status_code == 401


async def test_password_change_revokes_other_sessions(
    client: httpx2.AsyncClient, seeded: Creds
) -> None:
    current = (await _login(client, MAYA, seeded[MAYA]["password"])).json()
    other = (await _login(client, MAYA, seeded[MAYA]["password"])).json()
    headers = {"Authorization": f"Bearer {current['access_token']}"}
    weak = await client.post(
        "/api/v1/auth/password/change",
        json={"current_password": seeded[MAYA]["password"], "new_password": "password123"},
        headers=headers,
    )
    assert weak.status_code == 422
    wrong = await client.post(
        "/api/v1/auth/password/change",
        json={"current_password": "not-my-password", "new_password": "violet-harbor-lantern-42"},
        headers=headers,
    )
    assert wrong.status_code == 401
    changed = await client.post(
        "/api/v1/auth/password/change",
        json={
            "current_password": seeded[MAYA]["password"],
            "new_password": "violet-harbor-lantern-42",
        },
        headers=headers,
    )
    assert changed.status_code == 204
    assert (await client.get("/api/v1/auth/me", headers=headers)).status_code == 200
    assert (
        await client.get(
            "/api/v1/auth/me", headers={"Authorization": f"Bearer {other['access_token']}"}
        )
    ).status_code == 401
    assert (await _login(client, MAYA, seeded[MAYA]["password"])).status_code == 401
    assert (await _login(client, MAYA, "violet-harbor-lantern-42")).status_code == 200


async def test_password_reset_flow(
    container: AppContainer, client: httpx2.AsyncClient, seeded: Creds
) -> None:
    mailbox = CapturingEmailSender()
    container.email = mailbox
    session_before = (await _login(client, MAYA, seeded[MAYA]["password"])).json()

    known = await client.post("/api/v1/auth/password-reset/request", json={"email": MAYA})
    unknown = await client.post(
        "/api/v1/auth/password-reset/request", json={"email": "nobody@example.com"}
    )
    assert known.status_code == unknown.status_code == 202
    assert known.json() == unknown.json()  # no account enumeration
    assert len(mailbox.sent) == 1
    link = mailbox.sent[0].body.split("#token=")[1].split()[0]
    assert (
        "?" not in mailbox.sent[0].body.split("#token=")[0].split()[-1]
    )  # token only in the fragment

    confirm = await client.post(
        "/api/v1/auth/password-reset/confirm",
        json={"token": link, "new_password": "sapphire-meadow-compass-77"},
    )
    assert confirm.status_code == 204
    again = await client.post(
        "/api/v1/auth/password-reset/confirm",
        json={"token": link, "new_password": "another-strong-phrase-88"},
    )
    assert again.status_code == 422  # single use
    old = {"Authorization": f"Bearer {session_before['access_token']}"}
    assert (
        await client.get("/api/v1/auth/me", headers=old)
    ).status_code == 401  # all sessions revoked
    assert (await _login(client, MAYA, "sapphire-meadow-compass-77")).status_code == 200


async def test_expired_reset_token_is_rejected(
    container: AppContainer, client: httpx2.AsyncClient, seeded: Creds
) -> None:
    mailbox = CapturingEmailSender()
    container.email = mailbox
    await client.post("/api/v1/auth/password-reset/request", json={"email": MAYA})
    token = mailbox.sent[0].body.split("#token=")[1].split()[0]
    async with container.sessionmaker() as session:
        await session.execute(
            update(PasswordResetToken).values(expires_at=utc_now() - timedelta(minutes=1))
        )
        await session.commit()
    response = await client.post(
        "/api/v1/auth/password-reset/confirm",
        json={"token": token, "new_password": "sapphire-meadow-compass-77"},
    )
    assert response.status_code == 422


async def test_reset_requests_are_capped_per_account(
    container: AppContainer, client: httpx2.AsyncClient, seeded: Creds
) -> None:
    mailbox = CapturingEmailSender()
    container.email = mailbox
    for _ in range(5):
        await client.post("/api/v1/auth/password-reset/request", json={"email": MAYA})
    assert len(mailbox.sent) == 3


async def test_deactivated_user_loses_access_immediately(
    container: AppContainer, client: httpx2.AsyncClient, seeded: Creds
) -> None:
    tokens = (await _login(client, MAYA, seeded[MAYA]["password"])).json()
    async with container.sessionmaker() as session:
        await session.execute(update(User).where(User.email == MAYA).values(is_active=False))
        await session.commit()
    headers = {"Authorization": f"Bearer {tokens['access_token']}"}
    assert (await client.get("/api/v1/auth/me", headers=headers)).status_code == 401
    assert (await _login(client, MAYA, seeded[MAYA]["password"])).status_code == 401


def _auth(response: httpx2.Response) -> dict[str, Any]:
    return {"Authorization": f"Bearer {response.json()['access_token']}"}
