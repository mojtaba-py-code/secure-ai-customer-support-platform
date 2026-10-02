"""Alembic environment (async engine).

Migrations run as the schema *owner* role (``AEGIS_MIGRATION_DATABASE_URL``), while the
application connects as a restricted runtime role (``AEGIS_DATABASE_URL``) that cannot alter the
schema, drop tables or modify the audit trail. See ``docker/postgres/init`` and revision 0002.
"""

from __future__ import annotations

import asyncio
import os
from logging.config import fileConfig

from alembic import context
from sqlalchemy import pool
from sqlalchemy.engine import Connection
from sqlalchemy.ext.asyncio import async_engine_from_config

import aegis.models  # noqa: F401  (registers every table on Base.metadata)
from aegis.core.config import load_settings
from aegis.db.base import Base

config = context.config
if config.config_file_name is not None:
    # Keep loggers that already exist (the application's) enabled.
    fileConfig(config.config_file_name, disable_existing_loggers=False)

target_metadata = Base.metadata


def _database_url() -> str:
    url = os.environ.get("AEGIS_MIGRATION_DATABASE_URL") or os.environ.get("AEGIS_DATABASE_URL")
    if not url:
        url = load_settings().database_url.get_secret_value()
    return url


def run_migrations_offline() -> None:
    context.configure(
        url=_database_url(),
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
        render_as_batch=True,
    )
    with context.begin_transaction():
        context.run_migrations()


def _run(connection: Connection) -> None:
    context.configure(
        connection=connection,
        target_metadata=target_metadata,
        render_as_batch=connection.dialect.name == "sqlite",
        compare_type=True,
    )
    with context.begin_transaction():
        context.run_migrations()


async def run_migrations_online() -> None:
    section = config.get_section(config.config_ini_section, {})
    section["sqlalchemy.url"] = _database_url()
    engine = async_engine_from_config(section, prefix="sqlalchemy.", poolclass=pool.NullPool)
    async with engine.connect() as connection:
        await connection.run_sync(_run)
    await engine.dispose()


if context.is_offline_mode():
    run_migrations_offline()
else:
    asyncio.run(run_migrations_online())
