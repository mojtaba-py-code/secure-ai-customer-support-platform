"""Detection and redaction of personal data and secrets.

Three consumers with different needs:

* **Storage** - payment card numbers, CVV codes, credentials and government IDs are never
  persisted, even encrypted (PCI-DSS / data minimisation); everything else a customer writes
  is stored encrypted at rest.
* **LLM input** - all categories are replaced with typed placeholders before any text leaves
  for an external model provider; the model never needs the raw values (tools resolve the
  signed-in customer from the session, not from text).
* **Logs** - message content is not logged at all; this module is the backstop that scrubs
  any value that reaches a log record anyway.

Card numbers are confirmed with the Luhn checksum and IBANs with ISO 7064 mod-97 to keep
false positives (order numbers, amounts, dates) low. Reference numbers such as ``ORD-100234``
are masked out before phone detection runs.
"""

from __future__ import annotations

import re
from collections import Counter
from collections.abc import Callable
from dataclasses import dataclass, field
from enum import StrEnum

from aegis.domain.identifiers import REFERENCE_PATTERNS


class PiiKind(StrEnum):
    # Category names of detected data, not credentials.
    SECRET = "secret"  # noqa: S105  # nosec B105
    CARD = "card"
    CVV = "cvv"
    IBAN = "iban"
    SSN = "ssn"
    EMAIL = "email"
    PHONE = "phone"
    IP_ADDRESS = "ip_address"


ALL_KINDS: frozenset[PiiKind] = frozenset(PiiKind)
#: Never persisted, not even encrypted.
STORAGE_FORBIDDEN_KINDS: frozenset[PiiKind] = frozenset(
    {PiiKind.SECRET, PiiKind.CARD, PiiKind.CVV, PiiKind.SSN, PiiKind.IBAN}
)

_PLACEHOLDER = {
    PiiKind.SECRET: "[REDACTED_SECRET]",
    PiiKind.CARD: "[REDACTED_CARD]",
    PiiKind.CVV: "[REDACTED_CVV]",
    PiiKind.IBAN: "[REDACTED_IBAN]",
    PiiKind.SSN: "[REDACTED_SSN]",
    PiiKind.EMAIL: "[REDACTED_EMAIL]",
    PiiKind.PHONE: "[REDACTED_PHONE]",
    PiiKind.IP_ADDRESS: "[REDACTED_IP]",
}

_SECRET_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(
        r"-----BEGIN [A-Z ]{0,40}PRIVATE KEY-----[\s\S]{0,8000}?(?:-----END [A-Z ]{0,40}PRIVATE KEY-----|$)"
    ),
    re.compile(r"\bsk-ant-[A-Za-z0-9_\-]{16,200}"),
    re.compile(r"\bsk-[A-Za-z0-9_\-]{20,200}"),
    re.compile(r"\bpa-[A-Za-z0-9_\-]{20,200}"),
    re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    re.compile(r"\bgh[pousr]_[A-Za-z0-9]{30,120}\b"),
    re.compile(r"\beyJ[A-Za-z0-9_\-]{8,2000}\.[A-Za-z0-9_\-]{8,4000}\.[A-Za-z0-9_\-]{8,2000}"),
    re.compile(r"(?i)\bbearer\s+[A-Za-z0-9._~+/\-]{16,2000}=*"),
    re.compile(
        r"(?i)\b(?:postgres(?:ql)?|redis|rediss|mysql|mongodb(?:\+srv)?|amqp)(?:\+\w{1,20})?://\S{3,500}"
    ),
    # "password: hunter2!" / "my api key is x9_..." - the value must itself look like a secret
    # (contain a digit or symbol), so "my password is not working" is left alone.
    re.compile(
        r"(?i)\b(?:password|passwd|pwd|passcode|passphrase|api[_ -]?key|secret|token)\b"
        r"\s{0,3}(?:is|[:=])\s{0,3}"
        r"(?=[^\s,;]{0,199}[0-9!@#$%^&*()_+=\[\]{}<>?/\\|~-])[^\s,;]{6,200}"
    ),
)
_DATE_LIKE = re.compile(
    r"^\s*(?:\d{4}[-/.]\d{1,2}[-/.]\d{1,2}|\d{1,2}[-/.]\d{1,2}[-/.]\d{2,4})\s*$"
)
_CARD_CANDIDATE = re.compile(r"(?<![\d-])(?:\d[ -]?){12,18}\d(?![\d-])")
_CVV = re.compile(r"(?i)\b(?:cvv2?|cvc2?|csc|security code)\b\D{0,6}\d{3,4}\b")
_IBAN_CANDIDATE = re.compile(r"\b[A-Z]{2}\d{2}(?: ?[A-Z0-9]{4}){2,7}(?: ?[A-Z0-9]{1,4})?\b")
_SSN = re.compile(r"\b(?!000|666|9\d\d)\d{3}-(?!00)\d{2}-(?!0000)\d{4}\b")
_EMAIL = re.compile(
    r"(?i)\b[a-z0-9._%+\-]{1,64}@[a-z0-9\-]{1,63}(?:\.[a-z0-9\-]{1,63}){0,8}\.[a-z]{2,24}\b"
)
_PHONE = re.compile(
    r"(?<![\w+])(?:\+\d{1,3}[\s.\-]?)?(?:\(\d{1,4}\)[\s.\-]?)?\d{2,4}(?:[\s.\-]?\d{2,4}){1,4}(?![\w])"
)
_IPV4 = re.compile(
    r"\b(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\b"
)


@dataclass(frozen=True, slots=True)
class PiiMatch:
    kind: PiiKind
    start: int
    end: int


@dataclass(frozen=True, slots=True)
class RedactionResult:
    text: str
    counts: dict[str, int] = field(default_factory=dict)

    @property
    def redacted(self) -> bool:
        return bool(self.counts)


def luhn_valid(digits: str) -> bool:
    total = 0
    for index, char in enumerate(reversed(digits)):
        value = ord(char) - 48
        if index % 2 == 1:
            value *= 2
            if value > 9:
                value -= 9
        total += value
    return total % 10 == 0


def iban_valid(candidate: str) -> bool:
    compact = candidate.replace(" ", "").upper()
    if not 15 <= len(compact) <= 34:
        return False
    rearranged = compact[4:] + compact[:4]
    numeric = "".join(str(int(ch, 36)) for ch in rearranged)
    return int(numeric) % 97 == 1


def _phone_like(value: str) -> bool:
    digits = sum(ch.isdigit() for ch in value)
    if not 7 <= digits <= 15 or _DATE_LIKE.match(value):
        return False
    has_structure = value.lstrip().startswith(("+", "(")) or any(sep in value for sep in " .-")
    return has_structure or digits >= 10


def _overlaps(start: int, end: int, taken: list[tuple[int, int]]) -> bool:
    return any(start < t_end and end > t_start for t_start, t_end in taken)


def _card_like(candidate: str) -> bool:
    digits = re.sub(r"\D", "", candidate)
    return 13 <= len(digits) <= 19 and luhn_valid(digits)


# Detection order matters: earlier (higher-risk) kinds claim a span first.
_DETECTORS: tuple[
    tuple[PiiKind, tuple[re.Pattern[str], ...], Callable[[str], bool] | None], ...
] = (
    (PiiKind.SECRET, _SECRET_PATTERNS, None),
    (PiiKind.CVV, (_CVV,), None),
    (PiiKind.CARD, (_CARD_CANDIDATE,), _card_like),
    (PiiKind.IBAN, (_IBAN_CANDIDATE,), iban_valid),
    (PiiKind.SSN, (_SSN,), None),
    (PiiKind.EMAIL, (_EMAIL,), None),
    (PiiKind.IP_ADDRESS, (_IPV4,), None),
    (PiiKind.PHONE, (_PHONE,), _phone_like),
)


def find_pii(text: str, kinds: frozenset[PiiKind] = ALL_KINDS) -> list[PiiMatch]:
    """Non-overlapping PII matches, highest-risk categories first."""
    taken: list[tuple[int, int]] = [
        (m.start(), m.end())
        for pattern in REFERENCE_PATTERNS.values()
        for m in pattern.finditer(text)
    ]
    matches: list[PiiMatch] = []
    for kind, patterns, accept in _DETECTORS:
        if kind not in kinds:
            continue
        for pattern in patterns:
            for m in pattern.finditer(text):
                if accept is not None and not accept(m.group(0)):
                    continue
                if not _overlaps(m.start(), m.end(), taken):
                    taken.append((m.start(), m.end()))
                    matches.append(PiiMatch(kind, m.start(), m.end()))
    matches.sort(key=lambda match: match.start)
    return matches


def redact(text: str, kinds: frozenset[PiiKind] = ALL_KINDS) -> RedactionResult:
    """Replace every detected value of ``kinds`` with a typed placeholder."""
    matches = find_pii(text, kinds)
    if not matches:
        return RedactionResult(text=text)
    pieces: list[str] = []
    cursor = 0
    counts: Counter[str] = Counter()
    for match in matches:
        pieces.append(text[cursor : match.start])
        pieces.append(_PLACEHOLDER[match.kind])
        counts[match.kind.value] += 1
        cursor = match.end
    pieces.append(text[cursor:])
    return RedactionResult(text="".join(pieces), counts=dict(counts))


def redact_for_storage(text: str) -> RedactionResult:
    return redact(text, STORAGE_FORBIDDEN_KINDS)


def redact_for_llm(text: str) -> RedactionResult:
    return redact(text, ALL_KINDS)
