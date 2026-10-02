"""Shared fixtures.

By default every test gets a fresh in-memory SQLite database, an in-memory key-value store, an
embedded in-memory Qdrant and the deterministic offline model - no network, no Docker.
Set ``AEGIS_TEST_DATABASE_URL`` (``postgresql+asyncpg://...``) to run the same suite on
PostgreSQL.
"""

from __future__ import annotations

import json
import os
from collections.abc import AsyncIterator, Callable
from pathlib import Path
from typing import Any

import httpx2
import pytest
from cryptography.fernet import Fernet
from sqlalchemy import select, text

from aegis.bootstrap import AppContainer
from aegis.core.config import Settings
from aegis.db.base import Base
from aegis.kv.memory import MemoryKeyValueStore
from aegis.llm.base import LLMProvider
from aegis.main import create_app
from aegis.models import User
from aegis.security.principal import Principal
from aegis.seed import seed_demo_data

ROOT = Path(__file__).resolve().parents[1]
KB_DIR = ROOT / "data" / "knowledge_base"
TEST_DATABASE_URL = os.environ.get("AEGIS_TEST_DATABASE_URL")
FERNET_KEY = Fernet.generate_key().decode()

MAYA = "maya.thompson@example.com"  # VIP customer: delivered, shipped and processing orders
DANIEL = "daniel.okafor@example.com"  # refund window expired, failed payment
SOFIA = "sofia.rossi@example.com"  # refund under review, cancelled order
AGENT = "sam.rivera@acme.example"
AGENT2 = "jordan.lee@acme.example"
MANAGER = "priya.nair@acme.example"
ADMIN = "alex.morgan@acme.example"


def make_settings(**overrides: Any) -> Settings:
    values: dict[str, Any] = {
        "env": "test",
        "database_url": TEST_DATABASE_URL or "sqlite+aiosqlite:///:memory:",
        "jwt_secret": "test-jwt-secret-0123456789-abcdefghijklmnopqrstuv",
        "field_encryption_keys": FERNET_KEY,
        "argon2_time_cost": 1,
        "argon2_memory_cost_kib": 1024,
        "argon2_parallelism": 1,
        "email_backend": "disabled",
        "log_json": False,
        "log_level": "WARNING",
        "llm_provider": "offline",
    }
    values.update(overrides)
    return Settings(_env_file=None, **values)


async def build_container(
    settings: Settings | None = None, *, llm: LLMProvider | None = None, kv: Any | None = None
) -> AppContainer:
    container = AppContainer(settings or make_settings(), kv=kv or MemoryKeyValueStore(), llm=llm)
    async with container.engine.begin() as connection:
        if connection.dialect.name == "postgresql":
            await connection.execute(text("DROP SCHEMA public CASCADE"))
            await connection.execute(text("CREATE SCHEMA public"))
        await connection.run_sync(Base.metadata.create_all)
    return container


@pytest.fixture
def settings() -> Settings:
    return make_settings()


@pytest.fixture
async def container(settings: Settings) -> AsyncIterator[AppContainer]:
    c = await build_container(settings)
    try:
        yield c
    finally:
        await c.close()


async def seed(
    container: AppContainer, tmp_path: Path, *, with_kb: bool
) -> dict[str, dict[str, str]]:
    credentials = tmp_path / "credentials.json"
    await seed_demo_data(
        container, kb_dir=KB_DIR if with_kb else None, credentials_path=credentials
    )
    await container.startup()
    return json.loads(credentials.read_text(encoding="utf-8"))["accounts"]  # type: ignore[no-any-return]


@pytest.fixture
async def seeded(container: AppContainer, tmp_path: Path) -> dict[str, dict[str, str]]:
    """Demo business without the knowledge base (fast)."""
    return await seed(container, tmp_path, with_kb=False)


@pytest.fixture
async def seeded_kb(container: AppContainer, tmp_path: Path) -> dict[str, dict[str, str]]:
    """Demo business including the indexed knowledge base."""
    return await seed(container, tmp_path, with_kb=True)


@pytest.fixture
async def client(container: AppContainer) -> AsyncIterator[httpx2.AsyncClient]:
    app = create_app(container.settings, container=container)
    transport = httpx2.ASGITransport(app=app, client=("203.0.113.10", 51000))
    async with httpx2.AsyncClient(transport=transport, base_url="http://testserver") as http:
        yield http


LoginFn = Callable[[str], Any]


@pytest.fixture
def login(client: httpx2.AsyncClient) -> Callable[[dict[str, dict[str, str]], str], Any]:
    async def _login(credentials: dict[str, dict[str, str]], email: str) -> dict[str, str]:
        response = await client.post(
            "/api/v1/auth/login", json={"email": email, "password": credentials[email]["password"]}
        )
        assert response.status_code == 200, response.text
        return {"Authorization": f"Bearer {response.json()['access_token']}"}

    return _login


async def principal_for(container: AppContainer, email: str) -> Principal:
    async with container.sessionmaker() as session:
        user = (await session.execute(select(User).where(User.email == email))).scalar_one()
    return Principal(
        user_id=user.id,
        role=user.role,
        session_id=user.id,
        customer_id=user.customer_id,
        display_name=user.display_name,
    )
