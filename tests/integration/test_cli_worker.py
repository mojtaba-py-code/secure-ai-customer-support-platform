"""CLI commands, the worker, e-mail delivery, housekeeping and documentation drift."""

from __future__ import annotations

import json
import os
import sys
from datetime import timedelta
from pathlib import Path
from typing import Any

import pytest
from cryptography.fernet import Fernet
from sqlalchemy import select, text

from aegis import cli
from aegis.bootstrap import AppContainer, RequestServices
from aegis.core.time import utc_now
from aegis.domain.enums import ActionStatus, ActionType, KnowledgeCategory, KnowledgeVisibility
from aegis.models import AuthSession, IdempotencyRecord, PendingAction, RefreshToken, User
from aegis.security.crypto import FieldCipher
from aegis.security.principal import Principal
from aegis.services.email import (
    DevMailboxSender,
    DisabledEmailSender,
    OutgoingEmail,
    SmtpEmailSender,
)
from tests.conftest import KB_DIR, MAYA, ROOT, build_container, make_settings, seed

KEY_OLD = Fernet.generate_key().decode()


@pytest.fixture
def cli_env(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    monkeypatch.chdir(tmp_path)  # isolates the tests from any developer .env file
    database = tmp_path / "cli.db"
    monkeypatch.setenv("AEGIS_ENV", "development")
    monkeypatch.setenv("AEGIS_DATABASE_URL", f"sqlite+aiosqlite:///{database.as_posix()}")
    monkeypatch.setenv("AEGIS_JWT_SECRET", "cli-test-secret-0123456789-abcdefghijklmnop")
    monkeypatch.setenv("AEGIS_FIELD_ENCRYPTION_KEYS", KEY_OLD)
    monkeypatch.setenv("AEGIS_ARGON2_TIME_COST", "1")
    monkeypatch.setenv("AEGIS_ARGON2_MEMORY_COST_KIB", "1024")
    monkeypatch.setenv("AEGIS_ARGON2_PARALLELISM", "1")
    monkeypatch.setenv("AEGIS_EMAIL_BACKEND", "disabled")
    monkeypatch.setenv("AEGIS_LOG_LEVEL", "WARNING")
    monkeypatch.setenv("AEGIS_QDRANT_LOCATION", (tmp_path / "qdrant").as_posix())
    monkeypatch.delenv("AEGIS_MIGRATION_DATABASE_URL", raising=False)
    return tmp_path


def test_generate_secrets(capsys: pytest.CaptureFixture[str]) -> None:
    assert cli.main(["generate-secrets"]) == 0
    output = capsys.readouterr().out
    for name in (
        "AEGIS_JWT_SECRET=",
        "AEGIS_FIELD_ENCRYPTION_KEYS=",
        "POSTGRES_PASSWORD=",
        "AEGIS_DB_OWNER_PASSWORD=",
        "AEGIS_DB_APP_PASSWORD=",
        "REDIS_PASSWORD=",
    ):
        assert name in output
    fernet = next(
        line for line in output.splitlines() if line.startswith("AEGIS_FIELD_ENCRYPTION_KEYS=")
    )
    Fernet(fernet.split("=", 1)[1].encode())  # a valid key


def test_init_env_refuses_to_overwrite(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.chdir(tmp_path)
    target = tmp_path / ".env"
    assert cli.main(["init-env", "--path", str(target)]) == 0
    first = target.read_text(encoding="utf-8")
    assert "AEGIS_JWT_SECRET=" in first and "change-me" not in first
    assert cli.main(["init-env", "--path", str(target)]) == 1
    assert target.read_text(encoding="utf-8") == first
    assert cli.main(["init-env", "--path", str(target), "--force"]) == 0
    assert target.read_text(encoding="utf-8") != first
    if os.name != "nt":
        assert (target.stat().st_mode & 0o777) == 0o600


def test_check_config_hides_secrets(cli_env: Path, capsys: pytest.CaptureFixture[str]) -> None:
    assert cli.main(["check-config"]) == 0
    output = capsys.readouterr().out
    assert "sqlite" in output and "offline" in output
    assert "cli-test-secret" not in output and KEY_OLD not in output


def test_full_cli_lifecycle(
    cli_env: Path, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    assert cli.main(["migrate"]) == 0
    credentials = cli_env / "var" / "creds.json"
    assert cli.main(["seed", "--kb-dir", str(KB_DIR), "--credentials", str(credentials)]) == 0
    accounts = json.loads(credentials.read_text(encoding="utf-8"))["accounts"]
    assert MAYA in accounts and len(accounts) == 14
    assert (
        cli.main(["seed", "--kb-dir", str(KB_DIR), "--credentials", str(credentials)]) == 0
    )  # idempotent
    assert "nothing seeded" in capsys.readouterr().out
    assert cli.main(["index-kb"]) == 0
    assert cli.main(["worker", "--once"]) == 0
    capsys.readouterr()
    monkeypatch.setenv(
        "AEGIS_QDRANT_COLLECTION", "aegis_knowledge_v2"
    )  # e.g. a new embedding model
    assert cli.main(["index-kb", "--rebuild"]) == 0
    assert "rebuilt index" in capsys.readouterr().out

    monkeypatch.setenv("AEGIS_BOOTSTRAP_ADMIN_PASSWORD", "password123")
    assert cli.main(["create-admin", "--email", "boss@acme.example"]) == 1  # weak password refused
    monkeypatch.setenv("AEGIS_BOOTSTRAP_ADMIN_PASSWORD", "granite-harbor-lantern-58")
    assert cli.main(["create-admin", "--email", "not-an-email", "--name", "Boss"]) == 1
    capsys.readouterr()
    assert cli.main(["create-admin", "--email", "Boss@Acme.example", "--name", "Boss"]) == 0
    assert cli.main(["create-admin", "--email", "boss@acme.example", "--name", "Boss"]) == 1
    errors = capsys.readouterr().err
    assert "already exists" in errors and "granite-harbor" not in errors

    new_key = Fernet.generate_key().decode()
    monkeypatch.setenv("AEGIS_FIELD_ENCRYPTION_KEYS", f"{new_key},{KEY_OLD}")
    monkeypatch.setattr(cli, "ROTATION_BATCH_SIZE", 3)  # exercise the keyset pagination
    assert cli.main(["rotate-encryption"]) == 0
    assert "re-encrypted" in capsys.readouterr().out

    import sqlite3

    with sqlite3.connect(cli_env / "cli.db") as connection:
        phones = [row[0] for row in connection.execute("SELECT phone FROM customers")]
        contents = [
            row[0] for row in connection.execute("SELECT content FROM conversation_messages")
        ]
        admins = connection.execute("SELECT count(*) FROM users WHERE role = 'admin'").fetchone()[0]
        audited = connection.execute(
            "SELECT actor_role FROM audit_events WHERE action = 'admin.user_create'"
        ).fetchall()
    only_new_key = FieldCipher([new_key])
    assert len(phones) > 3 and all(only_new_key.decrypt(p).startswith("+1 555") for p in phones)
    assert all(only_new_key.decrypt(c) for c in contents)
    assert admins == 2
    assert audited == [("cli",)]


def test_rotation_covers_every_encrypted_column() -> None:
    discovered = {model.__name__: fields for model, fields in cli.encrypted_columns().items()}
    assert discovered == {
        "Customer": ("phone", "address"),
        "Order": ("shipping_address",),
        "Refund": ("customer_note",),
        "Conversation": ("summary",),
        "Message": ("content",),
        "SupportTicket": ("description",),
        "User": ("mfa_secret", "mfa_pending_secret"),
    }


class FakeResponse:
    def __init__(self, status_code: int) -> None:
        self.status_code = status_code


def test_api_healthcheck_uses_an_allowed_host(monkeypatch: pytest.MonkeyPatch) -> None:
    import httpx2

    calls: list[dict[str, Any]] = []

    def fake_get(url: str, **kwargs: Any) -> FakeResponse:
        calls.append({"url": url, **kwargs})
        return FakeResponse(200)

    monkeypatch.setattr(httpx2, "get", fake_get)
    monkeypatch.setenv("AEGIS_ALLOWED_HOSTS", "*.acme.example, support.acme.example")
    assert cli.main(["healthcheck"]) == 0
    assert calls[-1]["url"] == "http://127.0.0.1:8000/health/live"
    assert calls[-1]["headers"] == {"Host": "support.acme.example"}  # wildcards are skipped
    monkeypatch.delenv("AEGIS_ALLOWED_HOSTS")
    assert cli.main(["healthcheck", "--port", "9000"]) == 0
    assert calls[-1]["headers"] == {"Host": "localhost"}
    assert calls[-1]["url"] == "http://127.0.0.1:9000/health/live"

    monkeypatch.setattr(httpx2, "get", lambda url, **kwargs: FakeResponse(400))
    assert cli.main(["healthcheck"]) == 1

    def refused(url: str, **kwargs: Any) -> FakeResponse:
        raise httpx2.ConnectError("connection refused")

    monkeypatch.setattr(httpx2, "get", refused)
    assert cli.main(["healthcheck"]) == 1


def test_worker_healthcheck_reads_the_heartbeat(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    heartbeat = tmp_path / "worker.heartbeat"
    monkeypatch.delenv("AEGIS_WORKER_HEARTBEAT_FILE", raising=False)
    assert cli.main(["healthcheck", "--worker"]) == 1  # not configured
    monkeypatch.setenv("AEGIS_WORKER_HEARTBEAT_FILE", str(heartbeat))
    assert cli.main(["healthcheck", "--worker"]) == 1  # no heartbeat yet
    heartbeat.touch()
    assert cli.main(["healthcheck", "--worker"]) == 0
    stale = heartbeat.stat().st_mtime - 3_600
    os.utime(heartbeat, (stale, stale))
    assert cli.main(["healthcheck", "--worker"]) == 1
    assert cli.main(["healthcheck", "--worker", "--max-age", "7200"]) == 0


async def test_worker_loop_writes_its_heartbeat(tmp_path: Path) -> None:
    from aegis.workers.runner import run_worker

    heartbeat = tmp_path / "worker.heartbeat"
    settings = make_settings(
        database_url=f"sqlite+aiosqlite:///{(tmp_path / 'w.db').as_posix()}",
        worker_heartbeat_file=str(heartbeat),
    )
    container = await build_container(settings)
    await container.close()
    await run_worker(settings, once=True)
    assert heartbeat.exists()


def test_serve_uses_hardened_uvicorn_options(monkeypatch: pytest.MonkeyPatch) -> None:
    captured: dict[str, Any] = {}
    fake = type(sys)("uvicorn")
    fake.run = lambda app, **kwargs: captured.update(app=app, **kwargs)  # type: ignore[attr-defined]
    monkeypatch.setitem(sys.modules, "uvicorn", fake)
    assert cli.main(["serve", "--port", "9001"]) == 0
    assert captured["app"] == "aegis.main:create_app" and captured["factory"] is True
    assert captured["server_header"] is False and captured["proxy_headers"] is False
    assert captured["host"] == "127.0.0.1" and captured["port"] == 9001


async def test_email_senders(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    message = OutgoingEmail(to="maya@example.com", subject="Reset", body="Use this link")
    await DisabledEmailSender().send(message)

    mailbox = tmp_path / "mailbox"
    await DevMailboxSender(str(mailbox), "Acme <no-reply@acme.example>").send(message)
    [written] = list(mailbox.iterdir())
    assert "Subject: Reset" in written.read_text(encoding="utf-8")

    calls: list[str] = []

    class FakeSMTP:
        def __init__(self, host: str, port: int, timeout: float) -> None:
            calls.append(f"connect {host}:{port} timeout={timeout}")

        def __enter__(self) -> FakeSMTP:
            return self

        def __exit__(self, *args: object) -> None:
            calls.append("quit")

        def starttls(self, context: Any) -> None:
            calls.append(f"starttls verify={context.check_hostname}")

        def login(self, user: str, password: str) -> None:
            calls.append(f"login {user}")

        def send_message(self, email: Any) -> None:
            calls.append(f"send {email['To']}")

    monkeypatch.setattr("aegis.services.email.smtplib.SMTP", FakeSMTP)
    smtp = SmtpEmailSender(
        host="smtp.acme.example",
        port=587,
        username="mailer",
        password="pw",
        sender="no-reply@acme.example",
        timeout_seconds=5,
    )
    await smtp.send(message)
    assert calls == [
        "connect smtp.acme.example:587 timeout=5",
        "starttls verify=True",
        "login mailer",
        "send maya@example.com",
        "quit",
    ]


async def test_maintenance_expires_and_purges(container: AppContainer, tmp_path: Path) -> None:
    await seed(container, tmp_path, with_kb=False)
    past = utc_now() - timedelta(days=40)
    async with container.sessionmaker() as session:
        user = (await session.execute(select(User).where(User.email == MAYA))).scalar_one()
        services = RequestServices(container, session)
        principal = Principal(
            user_id=user.id,
            role=user.role,
            session_id=user.id,
            customer_id=user.customer_id,
            display_name="Maya",
        )
        conversation = await services.conversations.create(principal, subject=None)
        session.add(
            PendingAction(
                conversation_id=conversation.id,
                user_id=user.id,
                customer_id=user.customer_id,
                action_type=ActionType.ORDER_CANCELLATION,
                status=ActionStatus.PENDING,
                params={},
                summary="old",
                dedupe_key="cancel:old",
                created_at=past,
                expires_at=past + timedelta(minutes=15),
            )
        )
        session.add(
            IdempotencyRecord(
                user_id=user.id,
                scope="s",
                key="k" * 10,
                request_hash="h",
                created_at=past,
                expires_at=past + timedelta(days=1),
            )
        )
        auth = AuthSession(
            user_id=user.id, created_at=past, last_seen_at=past, expires_at=past + timedelta(days=1)
        )
        session.add(auth)
        await session.flush()
        session.add(
            RefreshToken(
                session_id=auth.id,
                token_hash="a" * 64,
                created_at=past,
                expires_at=past + timedelta(days=1),
            )
        )
        await session.commit()
        stats = await RequestServices(container, session).maintenance.run()
    assert stats["expired_actions"] == 1
    assert stats["purged_idempotency_keys"] == 1
    assert stats["purged_auth_records"] >= 2


async def test_worker_indexes_uploaded_documents(tmp_path: Path) -> None:
    from aegis.workers.runner import run_iteration

    container = await build_container(make_settings())
    try:
        await seed(container, tmp_path, with_kb=False)
        async with container.sessionmaker() as session:
            document = await RequestServices(container, session).knowledge.upload(
                None,
                filename="w.md",
                content_type="text/markdown",
                data=b"# Worker test\n\nThe worker indexes pending documents in the background.",
                title="Worker test",
                category=KnowledgeCategory.FAQ,
                visibility=KnowledgeVisibility.PUBLIC,
            )
        stats = await run_iteration(container, maintenance=True)
        assert stats["indexed"] == 1
        async with container.engine.connect() as connection:
            status = (
                await connection.execute(
                    text("SELECT status FROM knowledge_documents WHERE id = :id"),
                    {"id": document.id.hex},
                )
            ).scalar_one_or_none()
        assert status in (None, "indexed")  # SQLite stores UUIDs as hex strings
    finally:
        await container.close()


def test_generated_reference_docs_are_in_sync_with_the_code() -> None:
    """docs/configuration.md, docs/api-reference.md and docs/tools.md are rendered from the code."""
    sys.path.insert(0, str(ROOT / "scripts"))
    try:
        import generate_docs  # type: ignore[import-not-found]
    finally:
        sys.path.pop(0)
    documents = generate_docs.render_all()
    assert len(documents) == 3
    for path, expected in documents.items():
        current = path.read_text(encoding="utf-8") if path.exists() else ""
        assert current == expected, f"{path.name} is stale: run python scripts/generate_docs.py"
