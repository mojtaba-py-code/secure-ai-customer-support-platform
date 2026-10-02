"""PostgreSQL hardening: append-only audit trail and least-privilege runtime role.

* A trigger rejects UPDATE, DELETE and TRUNCATE on ``audit_events`` - even for the table owner
  unless the trigger is explicitly dropped (which is itself visible in the DDL history).
* If the runtime role exists (``AEGIS_DB_APP_ROLE``, default ``aegis_app``; created by
  ``docker/postgres/init``), it receives only DML on application tables and INSERT/SELECT on the
  audit table. It owns nothing, so it cannot ALTER or DROP tables.

No-op on SQLite (development/test databases).

Revision ID: 0002
Revises: 0001
"""

from __future__ import annotations

import os
import re
from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0002"
down_revision: str | None = "0001"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_ROLE_PATTERN = re.compile(r"^[a-z_][a-z0-9_]{0,62}$")


def _app_role() -> str:
    role = os.environ.get("AEGIS_DB_APP_ROLE", "aegis_app")
    if not _ROLE_PATTERN.fullmatch(role):
        msg = "AEGIS_DB_APP_ROLE must be a simple lowercase identifier"
        raise ValueError(msg)
    return role


def upgrade() -> None:
    bind = op.get_bind()
    if bind.dialect.name != "postgresql":
        return
    op.execute(
        """
        CREATE OR REPLACE FUNCTION aegis_reject_audit_change() RETURNS trigger
        LANGUAGE plpgsql AS $$
        BEGIN
            RAISE EXCEPTION 'audit_events is append-only (% blocked)', TG_OP;
        END;
        $$
        """
    )
    op.execute(
        "CREATE TRIGGER audit_events_append_only BEFORE UPDATE OR DELETE ON audit_events "
        "FOR EACH ROW EXECUTE FUNCTION aegis_reject_audit_change()"
    )
    op.execute(
        "CREATE TRIGGER audit_events_no_truncate BEFORE TRUNCATE ON audit_events "
        "FOR EACH STATEMENT EXECUTE FUNCTION aegis_reject_audit_change()"
    )

    role = _app_role()
    exists = bind.execute(sa.text("SELECT 1 FROM pg_roles WHERE rolname = :role"), {"role": role}).scalar()
    if not exists:
        return
    quoted = bind.dialect.identifier_preparer.quote(role)
    op.execute(f"GRANT USAGE ON SCHEMA public TO {quoted}")
    op.execute(f"GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO {quoted}")
    op.execute(f"REVOKE UPDATE, DELETE, TRUNCATE ON audit_events FROM {quoted}")
    op.execute(f"REVOKE INSERT, UPDATE, DELETE, TRUNCATE ON alembic_version FROM {quoted}")


def downgrade() -> None:
    bind = op.get_bind()
    if bind.dialect.name != "postgresql":
        return
    op.execute("DROP TRIGGER IF EXISTS audit_events_no_truncate ON audit_events")
    op.execute("DROP TRIGGER IF EXISTS audit_events_append_only ON audit_events")
    op.execute("DROP FUNCTION IF EXISTS aegis_reject_audit_change()")
