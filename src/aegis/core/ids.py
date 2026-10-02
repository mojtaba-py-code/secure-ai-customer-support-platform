"""Identifier generation.

Internal primary keys are random UUIDv4 values (unguessable, so an enumeration attack against
``/tickets/{id}`` finds nothing even before authorization runs). Customer-facing reference
numbers (``TCK-12345678``) are random too; the database's unique constraint is the final
guard against the rare collision and callers retry.
"""

from __future__ import annotations

import secrets


def reference_number(prefix: str, digits: int = 8) -> str:
    """Random, non-sequential business reference such as ``TCK-40718263``."""
    if not prefix.isalpha() or not prefix.isupper():
        msg = "prefix must be upper-case letters"
        raise ValueError(msg)
    first = secrets.choice("123456789")
    rest = "".join(secrets.choice("0123456789") for _ in range(digits - 1))
    return f"{prefix}-{first}{rest}"
