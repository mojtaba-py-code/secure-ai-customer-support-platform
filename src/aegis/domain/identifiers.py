"""Formats of customer-facing reference numbers.

These patterns are the single source of truth for (a) validating tool arguments produced by the
model, (b) deterministic entity extraction from customer messages and (c) the output guard's
grounding check, which rejects replies that mention a reference the evidence does not contain.
"""

from __future__ import annotations

import re

ORDER_NUMBER_RE = re.compile(r"\bORD-\d{6,10}\b", re.IGNORECASE)
TICKET_NUMBER_RE = re.compile(r"\bTCK-\d{6,10}\b", re.IGNORECASE)
REFUND_NUMBER_RE = re.compile(r"\bRFD-\d{6,10}\b", re.IGNORECASE)
SKU_RE = re.compile(r"\b[A-Z]{2,4}-[A-Z0-9]{2,8}-\d{2,4}\b", re.IGNORECASE)

ORDER_NUMBER_PATTERN = r"^ORD-\d{6,10}$"
TICKET_NUMBER_PATTERN = r"^TCK-\d{6,10}$"
SKU_PATTERN = r"^[A-Z]{2,4}-[A-Z0-9]{2,8}-\d{2,4}$"

REFERENCE_PATTERNS: dict[str, re.Pattern[str]] = {
    "order_number": ORDER_NUMBER_RE,
    "ticket_number": TICKET_NUMBER_RE,
    "refund_number": REFUND_NUMBER_RE,
    "sku": SKU_RE,
}


def normalize_reference(value: str) -> str:
    """Canonical form of a reference: trimmed and upper-cased."""
    return value.strip().upper()


def find_references(text: str) -> dict[str, list[str]]:
    """All reference numbers in ``text`` grouped by kind, canonicalised and de-duplicated."""
    found: dict[str, list[str]] = {}
    for kind, pattern in REFERENCE_PATTERNS.items():
        values = list(
            dict.fromkeys(normalize_reference(m.group(0)) for m in pattern.finditer(text))
        )
        if values:
            found[kind] = values
    return found
