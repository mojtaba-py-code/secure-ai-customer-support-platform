"""Users, sessions and single-use tokens."""

from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import Boolean, CheckConstraint, ForeignKey, Index, Integer, String
from sqlalchemy.orm import Mapped, mapped_column

from aegis.core.time import utc_now
from aegis.db.base import Base, EncryptedText, TimestampMixin, UUIDPrimaryKeyMixin, str_enum
from aegis.domain.enums import Role


class User(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    __tablename__ = "users"

    email: Mapped[str] = mapped_column(String(254), unique=True)
    password_hash: Mapped[str] = mapped_column(String(255))
    role: Mapped[Role] = mapped_column(str_enum(Role, "role"))
    display_name: Mapped[str] = mapped_column(String(120))
    customer_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("customers.id", ondelete="RESTRICT"), unique=True
    )
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    failed_login_count: Mapped[int] = mapped_column(Integer, default=0)
    locked_until: Mapped[datetime | None]
    last_login_at: Mapped[datetime | None]
    password_changed_at: Mapped[datetime] = mapped_column(default=utc_now)
    # Two-factor authentication (TOTP). Secrets are encrypted at rest like other sensitive columns.
    mfa_secret: Mapped[str | None] = mapped_column(EncryptedText())
    mfa_pending_secret: Mapped[str | None] = mapped_column(EncryptedText())
    mfa_enabled_at: Mapped[datetime | None]
    mfa_last_step: Mapped[int | None] = mapped_column(Integer)

    __table_args__ = (
        CheckConstraint("(role = 'customer') = (customer_id IS NOT NULL)", name="customer_link"),
        CheckConstraint("failed_login_count >= 0", name="failed_logins_non_negative"),
        CheckConstraint("email = lower(email)", name="email_lowercase"),
    )


class AuthSession(UUIDPrimaryKeyMixin, Base):
    """A login session; access tokens carry its id, refresh tokens rotate inside it."""

    __tablename__ = "auth_sessions"

    user_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"), index=True
    )
    created_at: Mapped[datetime] = mapped_column(default=utc_now)
    last_seen_at: Mapped[datetime] = mapped_column(default=utc_now)
    expires_at: Mapped[datetime]
    revoked_at: Mapped[datetime | None]
    revoked_reason: Mapped[str | None] = mapped_column(String(40))
    ip_address: Mapped[str | None] = mapped_column(String(45))
    user_agent: Mapped[str | None] = mapped_column(String(200))

    __table_args__ = (Index("ix_auth_sessions_expires_at", "expires_at"),)


class RefreshToken(UUIDPrimaryKeyMixin, Base):
    __tablename__ = "refresh_tokens"

    session_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("auth_sessions.id", ondelete="CASCADE"), index=True
    )
    token_hash: Mapped[str] = mapped_column(String(64), unique=True)
    created_at: Mapped[datetime] = mapped_column(default=utc_now)
    expires_at: Mapped[datetime]
    used_at: Mapped[datetime | None]

    __table_args__ = (Index("ix_refresh_tokens_expires_at", "expires_at"),)


class PasswordResetToken(UUIDPrimaryKeyMixin, Base):
    __tablename__ = "password_reset_tokens"

    user_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"), index=True
    )
    token_hash: Mapped[str] = mapped_column(String(64), unique=True)
    created_at: Mapped[datetime] = mapped_column(default=utc_now)
    expires_at: Mapped[datetime]
    used_at: Mapped[datetime | None]
    requested_ip: Mapped[str | None] = mapped_column(String(45))

    __table_args__ = (Index("ix_password_reset_tokens_expires_at", "expires_at"),)


class MfaRecoveryCode(UUIDPrimaryKeyMixin, Base):
    """A single-use recovery code (SHA-256 digest only) for when the authenticator is lost."""

    __tablename__ = "mfa_recovery_codes"

    user_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"), index=True
    )
    code_hash: Mapped[str] = mapped_column(String(64), unique=True)
    created_at: Mapped[datetime] = mapped_column(default=utc_now)
    used_at: Mapped[datetime | None]


class MfaChallenge(UUIDPrimaryKeyMixin, Base):
    """The second step of a login: issued after a correct password, redeemed once with a code."""

    __tablename__ = "mfa_challenges"

    user_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"), index=True
    )
    token_hash: Mapped[str] = mapped_column(String(64), unique=True)
    created_at: Mapped[datetime] = mapped_column(default=utc_now)
    expires_at: Mapped[datetime]
    used_at: Mapped[datetime | None]
    failed_attempts: Mapped[int] = mapped_column(Integer, default=0)
    ip_address: Mapped[str | None] = mapped_column(String(45))

    __table_args__ = (
        CheckConstraint("failed_attempts >= 0", name="failed_attempts_non_negative"),
        Index("ix_mfa_challenges_expires_at", "expires_at"),
    )
