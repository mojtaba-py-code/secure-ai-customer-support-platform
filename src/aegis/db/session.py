"""Async engine and session factory.

* PostgreSQL (production): pooled connections with pre-ping, a server-side statement timeout
  (a runaway query cannot hold a connection forever) and an idle-in-transaction timeout.
* SQLite (tests / no-Docker quick start): foreign keys enforced, WAL journal, busy timeout.

Queries are always built with SQLAlchemy constructs or bound parameters; no SQL string is ever
assembled from user input.
"""

from __future__ import annotations

from typing import Any

from sqlalchemy import event
from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)
from sqlalchemy.pool import StaticPool

from aegis.core.config import Settings


def create_engine(settings: Settings) -> AsyncEngine:
    url = settings.database_url.get_secret_value()
    if url.startswith("sqlite"):
        return _create_sqlite_engine(url, echo=settings.database_echo)
    return create_async_engine(
        url,
        echo=settings.database_echo,
        pool_size=settings.database_pool_size,
        max_overflow=settings.database_max_overflow,
        pool_timeout=settings.database_pool_timeout_seconds,
        pool_pre_ping=True,
        pool_recycle=1_800,
        connect_args={
            "server_settings": {
                "application_name": "aegis-support",
                "statement_timeout": str(settings.database_statement_timeout_ms),
                "idle_in_transaction_session_timeout": "60000",
            },
            "command_timeout": settings.database_statement_timeout_ms / 1000 + 5,
        },
    )


def _create_sqlite_engine(url: str, *, echo: bool) -> AsyncEngine:
    in_memory = ":memory:" in url or "mode=memory" in url
    kwargs: dict[str, Any] = {"echo": echo}
    if in_memory:
        kwargs["poolclass"] = StaticPool
        kwargs["connect_args"] = {"check_same_thread": False}
    engine = create_async_engine(url, **kwargs)

    @event.listens_for(engine.sync_engine, "connect")
    def _sqlite_pragmas(dbapi_connection: Any, _record: Any) -> None:
        cursor = dbapi_connection.cursor()
        cursor.execute("PRAGMA foreign_keys=ON")
        cursor.execute("PRAGMA busy_timeout=5000")
        if not in_memory:
            cursor.execute("PRAGMA journal_mode=WAL")
        cursor.close()

    return engine


def create_sessionmaker(engine: AsyncEngine) -> async_sessionmaker[AsyncSession]:
    return async_sessionmaker(engine, expire_on_commit=False, autoflush=False)
