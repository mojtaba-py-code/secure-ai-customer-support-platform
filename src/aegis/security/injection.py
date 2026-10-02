"""Heuristic prompt-injection and jailbreak detection.

This detector is ONE layer, deliberately not the security boundary. A determined attacker can
phrase an injection the patterns do not know, so the system is built to stay safe when the
detector misses: tools enforce authorization from the server-side session, write actions need
out-of-band confirmation, retrieved text is fenced as data, and the output guard checks every
reply. What the detector adds is *risk-adaptive behaviour*: a flagged turn loses its write
tools, repeated attempts escalate the conversation to a human, and security metrics/audit
events make attacks visible.

Scanning runs on several normalised forms of the text (NFKC, confusables folded, de-leeted,
separators squashed) so zero-width, homoglyph and leetspeak tricks do not bypass the patterns.
All patterns use bounded quantifiers (no catastrophic backtracking) and input is capped.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from enum import StrEnum

from aegis.security.text import count_invisible, detection_forms, has_mixed_scripts

MAX_SCAN_CHARS = 20_000


class RiskLevel(StrEnum):
    NONE = "none"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"

    @property
    def rank(self) -> int:
        return {"none": 0, "low": 1, "medium": 2, "high": 3}[self.value]


@dataclass(frozen=True, slots=True)
class InjectionAssessment:
    score: float
    level: RiskLevel
    categories: tuple[str, ...]

    @property
    def is_suspicious(self) -> bool:
        return self.level.rank >= RiskLevel.MEDIUM.rank


# One filler word (at least one character, so whitespace runs cannot be split ambiguously and
# the pattern stays linear-time).
_W = r"[\w'-]{1,30}"

_RULES: tuple[tuple[str, float, re.Pattern[str]], ...] = (
    (
        # "ignore all previous instructions" / "disregard your rules". Deliberately NOT
        # "ignore my previous message" (a normal thing for customers to write) and not
        # "override the refund policy" (a policy-exception request, handled by escalation).
        "instruction_override",
        0.6,
        re.compile(
            r"\b(?:ignore|disregard|forget)\b(?:\s+" + _W + r"){0,3}?\s+"
            r"(?:previous|prior|above|earlier|preceding|original|initial|system|all|any|your|the)\b"
            r"(?:\s+" + _W + r"){0,3}?\s+"
            r"(?:instructions?|rules|prompts?|directions|guidelines|constraints|programming)\b"
        ),
    ),
    (
        "instruction_override",
        0.6,
        re.compile(
            r"\b(?:ignore|disregard|forget)\s+(?:all\s+|everything\s+)?(?:the\s+)?(?:above|preceding)\b"
            r"|\b(?:new|updated|revised|real|actual)\s+(?:system\s+)?(?:instructions?|rules|prompt)\s*[:\-]"
        ),
    ),
    (
        "role_hijack",
        0.5,
        re.compile(
            r"\byou\s+are\s+now\s+(?:an?\s+|the\s+)?(?:dan|unrestricted|unfiltered|uncensored|jailbroken|evil|"
            r"in\s+(?:developer|god|dan)\s+mode|free\s+(?:of|from)|(?:ai|assistant|model|bot)\s+(?:without|with\s+no))"
            r"|\bfrom\s+now\s+on,?\s+you\s+(?:are|will\s+(?:act|behave|ignore|answer\s+without)|must\s+(?:ignore|act))"
            r"|\bact\s+as\s+(?:an?\s+|the\s+)?(?:admin|administrator|developer|system|root|superuser|"
            r"unrestricted|jailbroken)\b|\bpretend\s+(?:to\s+be|you\s+are)\b|\bdeveloper\s+mode\b|\bjailbreak"
            r"|\bdo\s+anything\s+now\b|\bdan\s+mode\b|\bgod\s+mode\b|\bno\s+(?:longer\s+)?(?:bound|restricted)\s+by\b"
        ),
    ),
    (
        "prompt_extraction",
        0.5,
        re.compile(
            r"\b(?:show|reveal|print|repeat|display|output|dump|leak|tell\s+me|what\s+(?:is|are|were))\b"
            r"(?:\s+" + _W + r"){0,3}?\s+"
            r"(?:system|hidden|initial|original|secret|internal|developer)\s+"
            r"(?:prompt|instructions?|message|rules|configuration|config)"
        ),
    ),
    (
        "prompt_extraction",
        0.45,
        re.compile(
            r"\b(?:repeat|print|output)\s+(?:everything|all\s+text|the\s+text)\s+(?:above|before)"
        ),
    ),
    (
        "delimiter_injection",
        0.5,
        re.compile(
            r"</?\s*(?:system|assistant|developer|instructions?|tool_result|tool|document|"
            r"customer_message|knowledge_base|conversation_history)\s*>|<\|im_(?:start|end)\|>|"
            r"\[/?inst\]|^\s*#{2,}\s*(?:system|instructions?)\b|```\s*system",
            re.MULTILINE,
        ),
    ),
    (
        "data_exfiltration",
        0.45,
        re.compile(
            r"\b(?:all|every|other|another|any|each)\s+(?:customers?|users?|clients?|accounts?)(?:'s|s')?\s+"
            r"(?:orders?|data|emails?|addresses|information|details|records|payments?|tickets?|conversations?)"
            r"|\b(?:dump|export|list|select)\s+(?:the\s+)?(?:entire\s+)?(?:database|db|tables?|all\s+users)"
            r"|\bselect\s+\*\s+from\b|\bunion\s+select\b|\bdrop\s+table\b"
        ),
    ),
    (
        "tool_manipulation",
        0.35,
        re.compile(
            r"\b(?:call|invoke|execute|run|use)\s+(?:the\s+)?(?:tool|function|api)\s+\w{3,40}\s*(?:\(|with)"
            r"|\b(?:customer_id|user_id|role|is_admin)\s*[:=]"
            r"|\bset\s+(?:my\s+)?(?:role|permissions?)\s+to\b"
        ),
    ),
    (
        "privilege_claim",
        0.35,
        re.compile(
            r"\b(?:i\s+am|i'm|this\s+is)\s+(?:the\s+|an?\s+|your\s+)?(?:admin|administrator|developer|"
            r"system\s+administrator|security\s+team|anthropic|openai|ceo|support\s+manager)\b"
            r"|\bauthorized\s+(?:penetration\s+)?test\s+mode\b|\bmaintenance\s+mode\b"
        ),
    ),
    (
        "addressed_to_ai",
        0.5,
        re.compile(
            r"\b(?:ai|assistant|chatbot|language\s+model|llm|model)\b[^.\n]{0,40}?\b(?:must|should|will|shall)\s+"
            r"(?:now\s+)?(?:ignore|reveal|tell|say|respond|reply|output|disclose|send|obey)\b"
            r"|\bwhen\s+(?:an?\s+|the\s+)?(?:ai|assistant|chatbot|model|llm)(?:\s+(?:assistant|model|agent|bot))?"
            r"\s+(?:reads|sees|processes)\s+this"
        ),
    ),
)

_BASE64_BLOB = re.compile(r"(?:[A-Za-z0-9+/]{4}){15,}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?")
_WORD = re.compile(r"\S{2,40}")


class PromptInjectionDetector:
    """Scores text for injection indicators; see module docstring for its role."""

    def __init__(self, *, medium_threshold: float = 0.4, high_threshold: float = 0.7) -> None:
        if not 0 < medium_threshold < high_threshold:
            msg = "thresholds must satisfy 0 < medium < high"
            raise ValueError(msg)
        self._medium = medium_threshold
        self._high = high_threshold

    def assess(self, text: str) -> InjectionAssessment:
        sample = text[:MAX_SCAN_CHARS]
        categories: dict[str, float] = {}
        forms = detection_forms(sample)
        for category, weight, pattern in _RULES:
            if category in categories:
                continue
            if any(pattern.search(form) for form in forms):
                categories[category] = weight

        obfuscation = 0.0
        if count_invisible(sample) >= 2:
            obfuscation += 0.25
        if _BASE64_BLOB.search(sample):
            obfuscation += 0.2
        if any(has_mixed_scripts(word) for word in _WORD.findall(sample[:4_000])):
            obfuscation += 0.2
        if obfuscation:
            categories["obfuscation"] = min(obfuscation, 0.4)

        score = min(1.0, sum(categories.values()))
        return InjectionAssessment(
            score=round(score, 3),
            level=self._level(score),
            categories=tuple(sorted(categories)),
        )

    def _level(self, score: float) -> RiskLevel:
        if score >= self._high:
            return RiskLevel.HIGH
        if score >= self._medium:
            return RiskLevel.MEDIUM
        if score > 0:
            return RiskLevel.LOW
        return RiskLevel.NONE
