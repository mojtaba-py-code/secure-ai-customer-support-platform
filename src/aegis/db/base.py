"""Declarative base, naming conventions and custom column types."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any

from sqlalchemy import JSON, DateTime, Enum, MetaData, Text, TypeDecorator, Uuid
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.engine import Dialect
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column

from aegis.core.time import ensure_utc, utc_now
from aegis.security.crypto import get_field_cipher

NAMING_CONVENTION = {
    "ix": "ix_%(column_0_label)s",
    "uq": "uq_%(table_name)s_%(column_0_name)s",
    "ck": "ck_%(table_name)s_%(constraint_name)s",
    "fk": "fk_%(table_name)s_%(column_0_name)s_%(referred_table_name)s",
    "pk": "pk_%(table_name)s",
}


class UTCDateTime(TypeDecorator[datetime]):
    """Timezone-aware UTC timestamps on every backend.

    PostgreSQL stores ``timestamptz``; SQLite has no time zones, so values are stored as naive
    UTC and re-labelled as UTC on the way out. Naive datetimes are rejected on the way in, which
    catches local-time bugs at the boundary instead of silently shifting data.
    """

    impl = DateTime(timezone=True)
    cache_ok = True

    def process_bind_param(self, value: datetime | None, dialect: Dialect) -> datetime | None:
        if value is None:
            return None
        if value.tzinfo is None:
            msg = "naive datetime passed to a UTCDateTime column"
            raise ValueError(msg)
        as_utc = value.astimezone(UTC)
        return as_utc.replace(tzinfo=None) if dialect.name == "sqlite" else as_utc

    def process_result_value(self, value: datetime | None, dialect: Dialect) -> datetime | None:
        return None if value is None else ensure_utc(value)


class EncryptedText(TypeDecorator[str]):
    """Text encrypted with the process-wide :class:`~aegis.security.crypto.FieldCipher`."""

    impl = Text
    cache_ok = True

    def process_bind_param(self, value: str | None, dialect: Dialect) -> str | None:
        return None if value is None else get_field_cipher().encrypt(value)

    def process_result_value(self, value: str | None, dialect: Dialect) -> str | None:
        return None if value is None else get_field_cipher().decrypt(value)


JSONType = JSON().with_variant(JSONB(), "postgresql")


def str_enum(enum_cls: type[StrEnum], name: str) -> Enum:
    """Portable enum column: VARCHAR + named CHECK constraint, values (not names) stored."""
    return Enum(
        enum_cls,
        name=name,
        native_enum=False,
        create_constraint=True,
        length=32,
        validate_strings=True,
        values_callable=lambda members: [m.value for m in members],
    )


class Base(DeclarativeBase):
    metadata = MetaData(naming_convention=NAMING_CONVENTION)
    type_annotation_map: dict[Any, Any] = {  # noqa: RUF012 - SQLAlchemy reads this mapping
        datetime: UTCDateTime(),
        uuid.UUID: Uuid(),
    }


class UUIDPrimaryKeyMixin:
    id: Mapped[uuid.UUID] = mapped_column(Uuid(), primary_key=True, default=uuid.uuid4)


class TimestampMixin:
    created_at: Mapped[datetime] = mapped_column(UTCDateTime(), default=utc_now, nullable=False)
    updated_at: Mapped[datetime] = mapped_column(
        UTCDateTime(), default=utc_now, onupdate=utc_now, nullable=False
    )
