"""Keyword-based intent classification.

Used (a) by the offline model, (b) as the fallback whenever the model's structured output is
unavailable or invalid, and (c) as a cross-check on the model's confidence. It is transparent
and deterministic; keywords live in ``intents.toml`` next to each intent.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from aegis.agents.intents import FALLBACK_INTENT, IntentDefinition, IntentRegistry
from aegis.agents.signals import MessageSignals
from aegis.domain.enums import Priority, Sentiment

_ORDER_RELATED = ("order_tracking", "refund_request", "cancellation", "payment_problem")


@dataclass(frozen=True, slots=True)
class RuleClassification:
    intent: IntentDefinition
    confidence: float
    priority: Priority
    requires_tool: bool
    requires_human: bool
    runner_up: str | None


class RuleBasedClassifier:
    def __init__(self, registry: IntentRegistry) -> None:
        self._registry = registry
        self._patterns: dict[str, list[tuple[re.Pattern[str], float]]] = {
            intent.name: [
                (
                    re.compile(r"\b" + re.escape(keyword.lower()) + r"\b"),
                    1.5 if " " in keyword else 1.0,
                )
                for keyword in intent.keywords
            ]
            for intent in registry.all()
        }

    def scores(self, text: str, signals: MessageSignals) -> dict[str, float]:
        lowered = text.lower()
        scores = {
            name: sum(weight for pattern, weight in patterns if pattern.search(lowered))
            for name, patterns in self._patterns.items()
        }
        if signals.account_compromise and "security_problem" in scores:
            scores["security_problem"] += 3.0
        if signals.legal_threat and "complaint" in scores:
            scores["complaint"] += 2.0
        if signals.sentiment is Sentiment.VERY_NEGATIVE and "complaint" in scores:
            scores["complaint"] += 1.0
        if signals.order_numbers:
            for name in _ORDER_RELATED:
                if name in scores and scores[name] > 0:
                    scores[name] += 0.5
            if "order_tracking" in scores and not any(
                scores[n] for n in _ORDER_RELATED if n in scores
            ):
                scores["order_tracking"] += 0.75
        if signals.references.get("ticket_number") and "general_question" in scores:
            scores["general_question"] += 1.0
        if signals.references.get("sku") and "product_question" in scores:
            scores["product_question"] += 1.0
        return scores

    def classify(self, text: str, signals: MessageSignals) -> RuleClassification:
        scores = self.scores(text, signals)
        ranked = sorted(scores.items(), key=lambda item: item[1], reverse=True)
        best_name, best = ranked[0]
        second_name, second = ranked[1] if len(ranked) > 1 else (None, 0.0)
        if best <= 0:
            intent = self._registry.resolve(FALLBACK_INTENT)
            confidence = 0.35
            runner_up = None
        else:
            intent = self._registry.resolve(best_name)
            # Competing with another *specific* intent is real ambiguity; competing with the
            # catch-all intent (whose keywords are generic, e.g. "policy") much less so.
            penalty = 0.05 if second_name == FALLBACK_INTENT else 0.12
            confidence = 0.5 + 0.15 * best - penalty * second
            confidence = max(0.3, min(0.92, confidence))
            runner_up = second_name if second > 0 else None
        priority = intent.default_priority
        if signals.urgent or signals.sentiment is Sentiment.VERY_NEGATIVE:
            priority = Priority.highest(priority, Priority.HIGH)
        requires_human = intent.always_escalate or signals.wants_human or signals.legal_threat
        return RuleClassification(
            intent=intent,
            confidence=round(confidence, 3),
            priority=priority,
            requires_tool=bool(signals.references) or intent.name in _ORDER_RELATED,
            requires_human=requires_human,
            runner_up=runner_up,
        )
