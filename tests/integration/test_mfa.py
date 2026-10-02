"""Two-factor authentication end to end: enrolment, sign-in, replay, lockout, policy, reset."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import httpx2
import pytest
from sqlalchemy import select, text

from aegis.bootstrap import AppContainer
from aegis.main import create_app
from aegis.models import AuditEvent, MfaRecoveryCode, User
from aegis.security.totp import current_step, hotp
from tests.conftest import ADMIN, AGENT, MAYA, build_container, make_settings, seed

Creds = dict[str, dict[str, str]]
T0 = 1_800_000_000.0  # a fixed wall clock for the TOTP tests (step boundaries are exact)


class Clock:
    def __init__(self, now: float) -> None:
        self.now = now

    def __call__(self) -> float:
        return self.now

    def advance(self, steps: int = 1) -> None:
        self.now += 30 * steps


@pytest.fixture
def clock(container: AppContainer) -> Clock:
    fake = Clock(T0)
    container.epoch_seconds = fake
    return fake


async def password_login(client: httpx2.AsyncClient, creds: Creds, email: str) -> dict[str, Any]:
    response = await client.post(
        "/api/v1/auth/login", json={"email": email, "password": creds[email]["password"]}
    )
    assert response.status_code == 200, response.text
    return dict(response.json())


def bearer(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


async def enrol(
    client: httpx2.AsyncClient, creds: Creds, email: str, clock: Clock
) -> tuple[str, list[str]]:
    """Enable MFA for ``email``; returns the secret and the recovery codes."""
    token = (await password_login(client, creds, email))["access_token"]
    setup = await client.post(
        "/api/v1/auth/mfa/setup",
        json={"password": creds[email]["password"]},
        headers=bearer(token),
    )
    assert setup.status_code == 200, setup.text
    secret = setup.json()["secret"]
    code = hotp(secret, current_step(clock.now))
    enabled = await client.post(
        "/api/v1/auth/mfa/enable", json={"code": code}, headers=bearer(token)
    )
    assert enabled.status_code == 200, enabled.text
    return secret, list(enabled.json()["recovery_codes"])


async def verify(client: httpx2.AsyncClient, mfa_token: str, code: str) -> httpx2.Response:
    return await client.post("/api/v1/auth/mfa/verify", json={"mfa_token": mfa_token, "code": code})


async def test_enrolment_requires_password_and_a_valid_code(
    client: httpx2.AsyncClient, seeded: Creds, clock: Clock
) -> None:
    token = (await password_login(client, seeded, MAYA))["access_token"]
    wrong = await client.post(
        "/api/v1/auth/mfa/setup", json={"password": "not-the-password"}, headers=bearer(token)
    )
    assert wrong.status_code == 401
    setup = await client.post(
        "/api/v1/auth/mfa/setup",
        json={"password": seeded[MAYA]["password"]},
        headers=bearer(token),
    )
    body = setup.json()
    assert body["otpauth_uri"].startswith("otpauth://totp/") and len(body["secret"]) == 32
    assert (
        await client.post("/api/v1/auth/mfa/enable", json={"code": "000000"}, headers=bearer(token))
    ).status_code == 422
    enabled = await client.post(
        "/api/v1/auth/mfa/enable",
        json={"code": hotp(body["secret"], current_step(clock.now))},
        headers=bearer(token),
    )
    assert enabled.status_code == 200
    assert len(enabled.json()["recovery_codes"]) == 10
    # Every session opened with the password alone ended.
    assert (await client.get("/api/v1/auth/me", headers=bearer(token))).status_code == 401


async def test_sign_in_needs_the_second_factor(
    client: httpx2.AsyncClient, seeded: Creds, clock: Clock
) -> None:
    secret, _ = await enrol(client, seeded, MAYA, clock)
    clock.advance()
    first = await password_login(client, seeded, MAYA)
    assert first["mfa_required"] is True and "access_token" not in first
    assert (await verify(client, first["mfa_token"], "123456")).status_code == 401
    good = await verify(client, first["mfa_token"], hotp(secret, current_step(clock.now)))
    assert good.status_code == 200
    me = await client.get("/api/v1/auth/me", headers=bearer(good.json()["access_token"]))
    assert me.json()["mfa_enabled"] is True
    # The challenge is single use, and the same code cannot be replayed on a new challenge.
    assert (
        await verify(client, first["mfa_token"], hotp(secret, current_step(clock.now)))
    ).status_code == 401
    second = await password_login(client, seeded, MAYA)
    assert (
        await verify(client, second["mfa_token"], hotp(secret, current_step(clock.now)))
    ).status_code == 401
    clock.advance()
    assert (
        await verify(client, second["mfa_token"], hotp(secret, current_step(clock.now)))
    ).status_code == 200


async def test_recovery_codes_work_once(
    client: httpx2.AsyncClient, seeded: Creds, clock: Clock
) -> None:
    _, codes = await enrol(client, seeded, MAYA, clock)
    challenge = await password_login(client, seeded, MAYA)
    assert (await verify(client, challenge["mfa_token"], codes[0].upper())).status_code == 200
    again = await password_login(client, seeded, MAYA)
    assert (await verify(client, again["mfa_token"], codes[0])).status_code == 401
    assert (await verify(client, again["mfa_token"], codes[1])).status_code == 200


async def test_wrong_codes_lock_the_account(
    client: httpx2.AsyncClient, seeded: Creds, clock: Clock, container: AppContainer
) -> None:
    secret, _ = await enrol(client, seeded, MAYA, clock)
    clock.advance()
    statuses = []
    for _ in range(2):
        challenge = await password_login(client, seeded, MAYA)
        for _ in range(3):
            statuses.append((await verify(client, challenge["mfa_token"], "000000")).status_code)
    assert statuses == [401] * 6
    # Locked: the password step fails generically, and even a correct code is refused.
    locked = await client.post(
        "/api/v1/auth/login", json={"email": MAYA, "password": seeded[MAYA]["password"]}
    )
    assert locked.status_code == 401
    async with container.sessionmaker() as session:
        user = (await session.execute(select(User).where(User.email == MAYA))).scalar_one()
        assert user.locked_until is not None
        events = (
            await session.execute(
                select(AuditEvent.action, AuditEvent.outcome).where(
                    AuditEvent.action == "auth.mfa_verify"
                )
            )
        ).all()
    assert len(events) >= 5 and all(outcome.value == "failure" for _, outcome in events)
    assert secret not in str(events)


async def test_a_challenge_dies_after_five_wrong_codes(tmp_path: Path) -> None:
    """Independent of the account lockout (set high here), one challenge allows five tries."""
    container = await build_container(make_settings(login_max_failed_attempts=20))
    fake = Clock(T0)
    container.epoch_seconds = fake
    try:
        creds = await seed(container, tmp_path, with_kb=False)
        app = create_app(container.settings, container=container)
        async with httpx2.AsyncClient(
            transport=httpx2.ASGITransport(app=app), base_url="http://testserver"
        ) as client:
            secret, _ = await enrol(client, creds, MAYA, fake)
            fake.advance()
            challenge = await password_login(client, creds, MAYA)
            for _ in range(5):
                assert (await verify(client, challenge["mfa_token"], "000000")).status_code == 401
            code = hotp(secret, current_step(fake.now))
            assert (await verify(client, challenge["mfa_token"], code)).status_code == 401
            fresh = await password_login(client, creds, MAYA)
            assert (await verify(client, fresh["mfa_token"], code)).status_code == 200
    finally:
        await container.close()


async def test_customers_can_turn_mfa_off_with_password_and_code(
    client: httpx2.AsyncClient, seeded: Creds, clock: Clock
) -> None:
    secret, _ = await enrol(client, seeded, MAYA, clock)
    clock.advance()
    challenge = await password_login(client, seeded, MAYA)
    token = (
        await verify(client, challenge["mfa_token"], hotp(secret, current_step(clock.now)))
    ).json()["access_token"]
    clock.advance()
    code = hotp(secret, current_step(clock.now))
    bad = await client.post(
        "/api/v1/auth/mfa/disable",
        json={"password": "wrong-password-123", "code": code},
        headers=bearer(token),
    )
    assert bad.status_code == 401
    off = await client.post(
        "/api/v1/auth/mfa/disable",
        json={"password": seeded[MAYA]["password"], "code": code},
        headers=bearer(token),
    )
    assert off.status_code == 204
    assert "access_token" in await password_login(client, seeded, MAYA)


async def test_secrets_and_recovery_codes_are_not_stored_in_clear(
    client: httpx2.AsyncClient, seeded: Creds, clock: Clock, container: AppContainer
) -> None:
    secret, codes = await enrol(client, seeded, MAYA, clock)
    async with container.engine.connect() as connection:
        raw: str = (
            await connection.execute(
                text("SELECT mfa_secret FROM users WHERE mfa_secret IS NOT NULL")
            )
        ).scalar_one()
    assert secret not in raw
    async with container.sessionmaker() as session:
        stored = [
            row.code_hash for row in (await session.execute(select(MfaRecoveryCode))).scalars()
        ]
    assert len(stored) == 10 and not set(codes) & set(stored)


async def test_staff_without_mfa_have_no_permissions_when_it_is_required(tmp_path: Path) -> None:
    container = await build_container(make_settings(mfa_required_for_staff=True))
    fake = Clock(T0)
    container.epoch_seconds = fake
    try:
        creds = await seed(container, tmp_path, with_kb=False)
        app = create_app(container.settings, container=container)
        async with httpx2.AsyncClient(
            transport=httpx2.ASGITransport(app=app), base_url="http://testserver"
        ) as client:
            token = (await password_login(client, creds, AGENT))["access_token"]
            me = (await client.get("/api/v1/auth/me", headers=bearer(token))).json()
            assert me["mfa_enrollment_required"] is True and me["permissions"] == []
            queue = await client.get("/api/v1/agent-desk/queue", headers=bearer(token))
            assert queue.status_code == 403
            orders = await client.get("/api/v1/orders", headers=bearer(token))
            assert orders.status_code == 403
            # Staff may not switch MFA off while the policy requires it.
            secret, _ = await enrol(client, creds, AGENT, fake)
            fake.advance()
            challenge = await password_login(client, creds, AGENT)
            staff_token = (
                await verify(client, challenge["mfa_token"], hotp(secret, current_step(fake.now)))
            ).json()["access_token"]
            me = (await client.get("/api/v1/auth/me", headers=bearer(staff_token))).json()
            assert (
                me["mfa_enrollment_required"] is False and "handoff:queue_read" in me["permissions"]
            )
            assert (
                await client.get("/api/v1/agent-desk/queue", headers=bearer(staff_token))
            ).status_code == 200
            fake.advance()
            refused = await client.post(
                "/api/v1/auth/mfa/disable",
                json={
                    "password": creds[AGENT]["password"],
                    "code": hotp(secret, current_step(fake.now)),
                },
                headers=bearer(staff_token),
            )
            assert refused.status_code == 409
    finally:
        await container.close()


async def test_administrators_reset_a_lost_second_factor(
    client: httpx2.AsyncClient, seeded: Creds, clock: Clock, container: AppContainer
) -> None:
    await enrol(client, seeded, AGENT, clock)
    admin = (await password_login(client, seeded, ADMIN))["access_token"]
    async with container.sessionmaker() as session:
        agent_id = (await session.execute(select(User.id).where(User.email == AGENT))).scalar_one()
        admin_id = (await session.execute(select(User.id).where(User.email == ADMIN))).scalar_one()
    reset = await client.post(f"/api/v1/admin/users/{agent_id}/reset-mfa", headers=bearer(admin))
    assert reset.status_code == 200 and reset.json()["mfa_enabled_at"] is None
    own = await client.post(f"/api/v1/admin/users/{admin_id}/reset-mfa", headers=bearer(admin))
    assert own.status_code == 409
    again = await client.post(f"/api/v1/admin/users/{agent_id}/reset-mfa", headers=bearer(admin))
    assert again.status_code == 409  # nothing left to reset
    # The agent signs in with the password alone again.
    assert "access_token" in await password_login(client, seeded, AGENT)
    async with container.sessionmaker() as session:
        actions = set((await session.execute(select(AuditEvent.action))).scalars())
    assert {"auth.mfa_setup", "auth.mfa_enable", "admin.user_reset_mfa"} <= actions


async def test_a_totp_step_can_be_claimed_only_once(container: AppContainer, seeded: Creds) -> None:
    """The atomic update behind replay protection: two claims of one step, one winner."""
    from aegis.repositories.identity import MfaRepository

    async with container.sessionmaker() as session:
        user_id = (await session.execute(select(User.id).where(User.email == MAYA))).scalar_one()
        repository = MfaRepository(session)
        step = current_step(T0)
        assert await repository.claim_step(user_id, step) is True
        assert await repository.claim_step(user_id, step) is False
        assert await repository.claim_step(user_id, step - 1) is False
        assert await repository.claim_step(user_id, step + 1) is True
        await session.commit()
