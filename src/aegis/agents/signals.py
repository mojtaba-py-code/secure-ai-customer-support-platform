"""Deterministic signals extracted from a customer message.

These run on every message regardless of what the model says, so the safety-relevant decisions
(human requested, legal threat, account compromise) cannot be talked out of by a prompt
injection that also targets the classifier.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from aegis.domain.enums import Sentiment
from aegis.domain.identifiers import find_references
from aegis.security.text import normalize_text

_WANTS_HUMAN = re.compile(
    r"\b(?:speak|talk|chat)\s+(?:to|with)\s+(?:a|an|some|the|your)?\s*(?:human|person|agent|representative|"
    r"real\s+person|someone|manager|supervisor|operator)\b"
    r"|\b(?:human|live|real)\s+(?:agent|person|support|representative)\b"
    r"|\bconnect\s+me\s+(?:to|with)\b|\btransfer\s+me\b|\bescalate\b"
)
_LEGAL = re.compile(
    r"\b(?:lawyer|attorney|solicitor|sue|suing|lawsuit|legal\s+action|court|small\s+claims|"
    r"consumer\s+protection|ombudsman|chargeback|trading\s+standards|regulator)\b"
)
_COMPROMISE = re.compile(
    r"\b(?:hacked|compromised|unauthori[sz]ed|fraud(?:ulent)?|stolen\s+(?:card|account|password)|"
    r"identity\s+theft|phishing|someone\s+(?:else\s+)?(?:logged|signed)\s+in|"
    r"(?:didn'?t|did\s+not)\s+(?:make|place|order)\s+(?:this|that|these|the)|not\s+my\s+(?:order|purchase))\b"
)
_URGENT = re.compile(r"\b(?:urgent|urgently|asap|immediately|right\s+now|emergency)\b")
_NEGATIVE = frozenset(
    [
        "angry",
        "furious",
        "terrible",
        "awful",
        "horrible",
        "worst",
        "unacceptable",
        "disappointed",
        "disappointing",
        "frustrated",
        "ridiculous",
        "useless",
        "disgusted",
        "hate",
        "scam",
        "rubbish",
        "pathetic",
        "incompetent",
        "annoyed",
        "upset",
    ]
)
_POSITIVE = frozenset(
    [
        "thanks",
        "thank",
        "great",
        "love",
        "perfect",
        "awesome",
        "excellent",
        "appreciate",
        "helpful",
        "wonderful",
    ]
)
_WORD = re.compile(r"[a-z']+")


@dataclass(frozen=True, slots=True)
class MessageSignals:
    wants_human: bool = False
    legal_threat: bool = False
    account_compromise: bool = False
    urgent: bool = False
    sentiment: Sentiment = Sentiment.NEUTRAL
    references: dict[str, list[str]] = field(default_factory=dict)

    @property
    def order_numbers(self) -> list[str]:
        return self.references.get("order_number", [])


def _sentiment(lowered: str, raw: str) -> Sentiment:
    words = _WORD.findall(lowered)
    negative = sum(1 for w in words if w in _NEGATIVE)
    positive = sum(1 for w in words if w in _POSITIVE)
    letters = [ch for ch in raw if ch.isalpha()]
    shouting = len(letters) >= 20 and sum(ch.isupper() for ch in letters) / len(letters) > 0.7
    if negative >= 2 or (negative >= 1 and (shouting or "!!" in raw)):
        return Sentiment.VERY_NEGATIVE
    if negative > positive:
        return Sentiment.NEGATIVE
    if positive > negative:
        return Sentiment.POSITIVE
    return Sentiment.NEUTRAL


def detect_signals(text: str) -> MessageSignals:
    normalized = normalize_text(text)
    lowered = normalized.lower()
    return MessageSignals(
        wants_human=bool(_WANTS_HUMAN.search(lowered)),
        legal_threat=bool(_LEGAL.search(lowered)),
        account_compromise=bool(_COMPROMISE.search(lowered)),
        urgent=bool(_URGENT.search(lowered)),
        sentiment=_sentiment(lowered, normalized),
        references=find_references(normalized),
    )
