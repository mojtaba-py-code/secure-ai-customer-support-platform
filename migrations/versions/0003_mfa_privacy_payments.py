"""Two-factor authentication, data-subject requests and payment-provider refunds.

* ``users``: encrypted TOTP secrets (active and pending enrolment), enrolment time and the last
  used time step (replay protection).
* ``mfa_recovery_codes``: single-use recovery codes (SHA-256 digests only).
* ``mfa_challenges``: the second login step (token digest, expiry, attempt counter).
* ``customers.erased_at`` / ``conversations.content_erased_at``: erasure and retention markers.
* ``refunds.provider_refund_id``: the payment provider's refund id (unique), used to match the
  provider's webhook events.

On PostgreSQL the runtime role (``AEGIS_DB_APP_ROLE``, if it exists) receives DML on the new
tables, like the tables of revision 0001 (see 0002).

Revision ID: 0003
Revises: 0002
"""

from __future__ import annotations

import os
import re
from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0003"
down_revision: str | None = "0002"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

NEW_TABLES = ("mfa_challenges", "mfa_recovery_codes")
_ROLE_PATTERN = re.compile(r"^[a-z_][a-z0-9_]{0,62}$")


def upgrade() -> None:
    op.create_table(
        "mfa_challenges",
        sa.Column("user_id", sa.Uuid(), nullable=False),
        sa.Column("token_hash", sa.String(length=64), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("used_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("failed_attempts", sa.Integer(), nullable=False),
        sa.Column("ip_address", sa.String(length=45), nullable=True),
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.CheckConstraint(
            "failed_attempts >= 0", name=op.f("ck_mfa_challenges_failed_attempts_non_negative")
        ),
        sa.ForeignKeyConstraint(
            ["user_id"],
            ["users.id"],
            name=op.f("fk_mfa_challenges_user_id_users"),
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_mfa_challenges")),
        sa.UniqueConstraint("token_hash", name=op.f("uq_mfa_challenges_token_hash")),
    )
    with op.batch_alter_table("mfa_challenges", schema=None) as batch_op:
        batch_op.create_index("ix_mfa_challenges_expires_at", ["expires_at"], unique=False)
        batch_op.create_index(batch_op.f("ix_mfa_challenges_user_id"), ["user_id"], unique=False)

    op.create_table(
        "mfa_recovery_codes",
        sa.Column("user_id", sa.Uuid(), nullable=False),
        sa.Column("code_hash", sa.String(length=64), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("used_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.ForeignKeyConstraint(
            ["user_id"],
            ["users.id"],
            name=op.f("fk_mfa_recovery_codes_user_id_users"),
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_mfa_recovery_codes")),
        sa.UniqueConstraint("code_hash", name=op.f("uq_mfa_recovery_codes_code_hash")),
    )
    with op.batch_alter_table("mfa_recovery_codes", schema=None) as batch_op:
        batch_op.create_index(
            batch_op.f("ix_mfa_recovery_codes_user_id"), ["user_id"], unique=False
        )

    with op.batch_alter_table("conversations", schema=None) as batch_op:
        batch_op.add_column(
            sa.Column("content_erased_at", sa.DateTime(timezone=True), nullable=True)
        )

    with op.batch_alter_table("customers", schema=None) as batch_op:
        batch_op.add_column(sa.Column("erased_at", sa.DateTime(timezone=True), nullable=True))

    with op.batch_alter_table("refunds", schema=None) as batch_op:
        batch_op.add_column(sa.Column("provider_refund_id", sa.String(length=64), nullable=True))
        batch_op.create_unique_constraint(
            batch_op.f("uq_refunds_provider_refund_id"), ["provider_refund_id"]
        )

    with op.batch_alter_table("users", schema=None) as batch_op:
        batch_op.add_column(sa.Column("mfa_secret", sa.Text(), nullable=True))
        batch_op.add_column(sa.Column("mfa_pending_secret", sa.Text(), nullable=True))
        batch_op.add_column(sa.Column("mfa_enabled_at", sa.DateTime(timezone=True), nullable=True))
        batch_op.add_column(sa.Column("mfa_last_step", sa.Integer(), nullable=True))

    _grant_runtime_role()


def _grant_runtime_role() -> None:
    bind = op.get_bind()
    if bind.dialect.name != "postgresql":
        return
    role = os.environ.get("AEGIS_DB_APP_ROLE", "aegis_app")
    if not _ROLE_PATTERN.fullmatch(role):
        msg = "AEGIS_DB_APP_ROLE must be a simple lowercase identifier"
        raise ValueError(msg)
    exists = bind.execute(
        sa.text("SELECT 1 FROM pg_roles WHERE rolname = :role"), {"role": role}
    ).scalar()
    if not exists:
        return
    quoted = bind.dialect.identifier_preparer.quote(role)
    for table in NEW_TABLES:
        op.execute(f"GRANT SELECT, INSERT, UPDATE, DELETE ON {table} TO {quoted}")


def downgrade() -> None:
    with op.batch_alter_table("users", schema=None) as batch_op:
        batch_op.drop_column("mfa_last_step")
        batch_op.drop_column("mfa_enabled_at")
        batch_op.drop_column("mfa_pending_secret")
        batch_op.drop_column("mfa_secret")

    with op.batch_alter_table("refunds", schema=None) as batch_op:
        batch_op.drop_constraint(batch_op.f("uq_refunds_provider_refund_id"), type_="unique")
        batch_op.drop_column("provider_refund_id")

    with op.batch_alter_table("customers", schema=None) as batch_op:
        batch_op.drop_column("erased_at")

    with op.batch_alter_table("conversations", schema=None) as batch_op:
        batch_op.drop_column("content_erased_at")

    with op.batch_alter_table("mfa_recovery_codes", schema=None) as batch_op:
        batch_op.drop_index(batch_op.f("ix_mfa_recovery_codes_user_id"))
    op.drop_table("mfa_recovery_codes")

    with op.batch_alter_table("mfa_challenges", schema=None) as batch_op:
        batch_op.drop_index(batch_op.f("ix_mfa_challenges_user_id"))
        batch_op.drop_index("ix_mfa_challenges_expires_at")
    op.drop_table("mfa_challenges")
