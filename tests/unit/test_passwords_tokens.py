from __future__ import annotations

import asyncio
import threading
import time
import uuid
from datetime import UTC, datetime, timedelta

import jwt
import pytest

from aegis.core.errors import AuthenticationFailed
from aegis.domain.enums import Role
from aegis.security.passwords import PasswordHasher, password_policy_problems
from aegis.security.tokens import TokenService, generate_opaque_token, hash_opaque_token

SECRET = "unit-test-secret-0123456789-abcdefghijklmnopqrstuvwxyz-0123456789ABCDEFGH"


@pytest.fixture
def hasher() -> PasswordHasher:
    return PasswordHasher(time_cost=1, memory_cost_kib=1024, parallelism=1)


def test_hash_and_verify(hasher: PasswordHasher) -> None:
    stored = hasher.hash("correct horse battery staple")
    assert stored.startswith("$argon2id$")
    assert hasher.verify(stored, "correct horse battery staple")
    assert not hasher.verify(stored, "wrong password")
    assert not hasher.verify("not-a-hash", "whatever")


async def test_async_hashing(hasher: PasswordHasher) -> None:
    stored = await hasher.hash_async("async-password-123")
    assert await hasher.verify_async(stored, "async-password-123")
    await hasher.verify_dummy_async("anything")


async def test_concurrent_hashing_is_capped(monkeypatch: pytest.MonkeyPatch) -> None:
    """A login flood cannot run unbounded Argon2 work (memory) in parallel."""
    capped = PasswordHasher(time_cost=1, memory_cost_kib=1024, parallelism=1, max_concurrent=2)
    lock = threading.Lock()
    state = {"now": 0, "peak": 0}

    def slow_hash(password: str) -> str:
        with lock:
            state["now"] += 1
            state["peak"] = max(state["peak"], state["now"])
        time.sleep(0.05)
        with lock:
            state["now"] -= 1
        return "hash"

    monkeypatch.setattr(capped, "hash", slow_hash)
    await asyncio.gather(*(capped.hash_async(f"password-{i}") for i in range(6)))
    assert state["peak"] == 2


def test_overlong_password_is_rejected(hasher: PasswordHasher) -> None:
    with pytest.raises(ValueError, match="too long"):
        hasher.hash("x" * 129)
    assert not hasher.verify(hasher.hash("short-enough-1"), "x" * 500)


def test_rehash_detection() -> None:
    weak = PasswordHasher(time_cost=1, memory_cost_kib=1024, parallelism=1)
    strong = PasswordHasher(time_cost=2, memory_cost_kib=2048, parallelism=1)
    assert strong.needs_rehash(weak.hash("password-to-upgrade"))
    assert not weak.needs_rehash(weak.hash("password-to-upgrade"))


@pytest.mark.parametrize(
    ("password", "problem"),
    [
        ("short", "at least"),
        ("password123", "too common"),
        ("aaaaaaaaaaaaaaa", "repetitive"),
        ("maya.thompson-2026!", "e-mail"),
    ],
)
def test_password_policy(password: str, problem: str) -> None:
    problems = password_policy_problems(password, min_length=12, email="maya.thompson@example.com")
    assert any(problem in p for p in problems)


def test_strong_password_passes_policy() -> None:
    assert (
        password_policy_problems(
            "violet-harbor-lantern-42", min_length=12, email="maya@example.com"
        )
        == []
    )


def make_service(**overrides: object) -> TokenService:
    values: dict[str, object] = {
        "secret": SECRET,
        "issuer": "aegis-support",
        "audience": "aegis-support-api",
        "access_ttl_seconds": 900,
    }
    values.update(overrides)
    return TokenService(**values)  # type: ignore[arg-type]


def test_access_token_roundtrip() -> None:
    service = make_service()
    user_id, session_id = uuid.uuid4(), uuid.uuid4()
    token, expires = service.issue_access_token(
        user_id=user_id, session_id=session_id, role=Role.CUSTOMER
    )
    claims = service.decode_access_token(token)
    assert claims.user_id == user_id
    assert claims.session_id == session_id
    assert claims.role is Role.CUSTOMER
    assert claims.expires_at == expires


def _claims(**overrides: object) -> dict[str, object]:
    now = datetime.now(UTC)
    claims: dict[str, object] = {
        "iss": "aegis-support",
        "aud": "aegis-support-api",
        "sub": str(uuid.uuid4()),
        "sid": str(uuid.uuid4()),
        "role": "admin",
        "typ": "access",
        "jti": "x",
        "iat": now,
        "nbf": now,
        "exp": now + timedelta(minutes=5),
    }
    claims.update(overrides)
    return claims


@pytest.mark.parametrize(
    "token_factory",
    [
        lambda: jwt.encode(
            _claims(),
            "another-secret-0123456789-abcdefghijklmnopqrstuvwxyz-0123456789ABCDEFGH",
            algorithm="HS256",
        ),
        lambda: jwt.encode(
            _claims(exp=datetime.now(UTC) - timedelta(minutes=5)), SECRET, algorithm="HS256"
        ),
        lambda: jwt.encode(_claims(aud="someone-else"), SECRET, algorithm="HS256"),
        lambda: jwt.encode(_claims(iss="evil"), SECRET, algorithm="HS256"),
        lambda: jwt.encode(_claims(typ="refresh"), SECRET, algorithm="HS256"),
        lambda: jwt.encode(
            {k: v for k, v in _claims().items() if k != "sid"}, SECRET, algorithm="HS256"
        ),
        lambda: jwt.encode(_claims(role="superuser"), SECRET, algorithm="HS256"),
        lambda: jwt.encode(_claims(), SECRET, algorithm="HS512"),
        lambda: "eyJhbGciOiJub25lIn0." + jwt.utils.base64url_encode(b'{"sub":"x"}').decode() + ".",
        lambda: "x" * 5_000,
        lambda: "",
    ],
    ids=[
        "wrong-key",
        "expired",
        "wrong-audience",
        "wrong-issuer",
        "wrong-type",
        "missing-claim",
        "unknown-role",
        "algorithm-confusion",
        "alg-none",
        "oversized",
        "empty",
    ],
)
def test_invalid_tokens_are_rejected(token_factory: object) -> None:
    token = token_factory()  # type: ignore[operator]
    with pytest.raises(AuthenticationFailed):
        make_service().decode_access_token(token)


def test_opaque_tokens_are_random_and_hashed() -> None:
    first, second = generate_opaque_token(), generate_opaque_token()
    assert first != second
    assert len(first) >= 40
    assert hash_opaque_token(first) == hash_opaque_token(first)
    assert hash_opaque_token(first) != first
