"""Time helpers: every timestamp in the system is timezone-aware UTC."""

from __future__ import annotations

from collections.abc import Callable
from datetime import UTC, date, datetime

Clock = Callable[[], datetime]


def utc_now() -> datetime:
    return datetime.now(UTC)


def utc_today() -> date:
    return utc_now().date()


def ensure_utc(value: datetime) -> datetime:
    """Return ``value`` as an aware UTC datetime; naive values are assumed to already be UTC."""
    if value.tzinfo is None:
        return value.replace(tzinfo=UTC)
    return value.astimezone(UTC)


def day_key(now: datetime | None = None) -> str:
    """``YYYYMMDD`` for daily counters (budgets, quotas)."""
    return (now or utc_now()).strftime("%Y%m%d")
