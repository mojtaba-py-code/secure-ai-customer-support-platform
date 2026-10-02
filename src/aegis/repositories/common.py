"""Helpers shared by repositories."""

from __future__ import annotations

from typing import Any

MAX_PAGE_SIZE = 100
MAX_OFFSET = 10_000


def clamp_page(limit: int, offset: int) -> tuple[int, int]:
    """Bound pagination so a request cannot ask the database for unbounded work."""
    return max(1, min(limit, MAX_PAGE_SIZE)), max(0, min(offset, MAX_OFFSET))


def escape_like(term: str) -> str:
    """Escape LIKE wildcards in user input (used with ``escape='\\\\'``)."""
    return term.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")


def affected_rows(result: Any) -> int:
    """Row count of an UPDATE/DELETE (``CursorResult.rowcount``), typed as ``int``."""
    return int(getattr(result, "rowcount", 0) or 0)
