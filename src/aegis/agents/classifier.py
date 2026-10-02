"""Intent classification with structured output and a deterministic fallback.

The model returns JSON constrained by a schema; the JSON is then validated again with Pydantic
(enumerations, ranges, reference formats). Anything the model claims is cross-checked:

* order numbers are accepted only if they literally occur in the customer's message;
* priority can be raised by the model but never lowered below the intent's default or below
  what deterministic signals demand;
* ``requires_human`` is OR-ed with deterministic signals (a prompt injection cannot switch off
  escalation of "my account was hacked");
* if the model's intent disagrees with a confident rule-based reading, confidence is capped so
  the policy asks a clarifying question instead of acting on a shaky label.

Malformed output, refusals, timeouts or an exhausted budget fall back to the rule classifier.
"""

from __future__ import annotations

import json
import logging
import uuid
from dataclasses import dataclass, field
from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field, StringConstraints, ValidationError

from aegis.agents.intents import IntentDefinition, IntentRegistry
from aegis.agents.prompts import build_classifier_system_prompt, render_customer_message
from aegis.agents.rules import RuleBasedClassifier, RuleClassification
from aegis.agents.signals import MessageSignals
from aegis.core.errors import AegisError
from aegis.domain.enums import Priority, Sentiment
from aegis.domain.identifiers import ORDER_NUMBER_PATTERN
from aegis.llm.gateway import LLMGateway
from aegis.llm.types import ChatMessage, LLMRequest, LLMTask, StopReason
from aegis.security.text import truncate

logger = logging.getLogger(__name__)


class LLMClassification(BaseModel):
    model_config = ConfigDict(extra="forbid")

    intent: str
    priority: Priority
    sentiment: Sentiment
    confidence: float = Field(ge=0.0, le=1.0)
    requires_tool: bool
    requires_human: bool
    order_numbers: list[Annotated[str, StringConstraints(pattern=ORDER_NUMBER_PATTERN)]] = Field(
        max_length=5
    )
    language: Annotated[str, StringConstraints(pattern=r"^[a-z]{2}$")]
    summary: Annotated[str, StringConstraints(max_length=300)]


@dataclass(frozen=True, slots=True)
class Classification:
    intent: IntentDefinition
    priority: Priority
    sentiment: Sentiment
    confidence: float
    requires_tool: bool
    requires_human: bool
    language: str
    summary: str
    source: Literal["llm", "rules", "rules_fallback"]
    references: dict[str, list[str]] = field(default_factory=dict)
    degraded: bool = False


def classification_schema(registry: IntentRegistry) -> dict[str, object]:
    return {
        "type": "object",
        "properties": {
            "intent": {"type": "string", "enum": list(registry.names)},
            "priority": {"type": "string", "enum": [p.value for p in Priority]},
            "sentiment": {"type": "string", "enum": [s.value for s in Sentiment]},
            "confidence": {"type": "number"},
            "requires_tool": {"type": "boolean"},
            "requires_human": {"type": "boolean"},
            "order_numbers": {"type": "array", "items": {"type": "string"}},
            "language": {"type": "string"},
            "summary": {"type": "string"},
        },
        "required": [
            "intent",
            "priority",
            "sentiment",
            "confidence",
            "requires_tool",
            "requires_human",
            "order_numbers",
            "language",
            "summary",
        ],
        "additionalProperties": False,
    }


def _extract_json(text: str) -> object:
    stripped = text.strip()
    if stripped.startswith("```"):
        stripped = stripped.strip("`")
        stripped = stripped.removeprefix("json").strip()
    start, end = stripped.find("{"), stripped.rfind("}")
    if start == -1 or end < start:
        msg = "no JSON object in model output"
        raise ValueError(msg)
    return json.loads(stripped[start : end + 1])


class IntentClassifier:
    def __init__(
        self,
        *,
        gateway: LLMGateway,
        registry: IntentRegistry,
        rules: RuleBasedClassifier,
        max_output_tokens: int,
    ) -> None:
        self._gateway = gateway
        self._registry = registry
        self._rules = rules
        self._max_tokens = max_output_tokens
        self._system = build_classifier_system_prompt(registry)
        self._schema = classification_schema(registry)

    async def classify(
        self,
        text: str,
        *,
        signals: MessageSignals,
        previous_intent: str | None,
        user_id: uuid.UUID | None,
        conversation_id: uuid.UUID | None,
        user_ref: str | None = None,
    ) -> Classification:
        rules = self._rules.classify(text, signals)
        prompt = render_customer_message(text)
        if previous_intent:
            prompt = (
                f"<turn_context>\nprevious_intent: {previous_intent}\n</turn_context>\n\n{prompt}"
            )
        request = LLMRequest(
            task=LLMTask.CLASSIFY,
            system=self._system,
            messages=[ChatMessage(role="user", text=prompt)],
            response_schema=self._schema,
            max_output_tokens=self._max_tokens,
            metadata={"user_ref": user_ref or "", "customer_text": text},
        )
        try:
            response = await self._gateway.complete(
                request, user_id=user_id, conversation_id=conversation_id
            )
        except AegisError as exc:
            logger.warning(
                "classification fell back to rules",
                extra={"event": "classify.fallback", "error": exc.code},
            )
            return self._from_rules(rules, signals, source="rules_fallback", degraded=True)
        if response.stop_reason is not StopReason.END_TURN:
            logger.warning(
                "classification output unusable",
                extra={"event": "classify.fallback", "stop_reason": response.stop_reason.value},
            )
            return self._from_rules(rules, signals, source="rules_fallback", degraded=True)
        try:
            parsed = LLMClassification.model_validate(_extract_json(response.text))
        except (ValueError, ValidationError):
            logger.warning("classification output malformed", extra={"event": "classify.malformed"})
            return self._from_rules(
                rules, signals, source="rules_fallback", degraded=response.degraded
            )
        intent = self._registry.get(parsed.intent)
        if intent is None:
            return self._from_rules(
                rules, signals, source="rules_fallback", degraded=response.degraded
            )
        return self._merge(parsed, intent, rules, signals, text, degraded=response.degraded)

    def _merge(
        self,
        parsed: LLMClassification,
        intent: IntentDefinition,
        rules: RuleClassification,
        signals: MessageSignals,
        text: str,
        *,
        degraded: bool,
    ) -> Classification:
        upper_text = text.upper()
        references = {k: list(v) for k, v in signals.references.items()}
        grounded_orders = [o for o in parsed.order_numbers if o.upper() in upper_text]
        if grounded_orders:
            merged = list(
                dict.fromkeys(
                    [*references.get("order_number", []), *(o.upper() for o in grounded_orders)]
                )
            )
            references["order_number"] = merged

        priority = Priority.highest(parsed.priority, intent.default_priority, rules.priority)
        confidence = parsed.confidence
        if rules.intent.name != intent.name and rules.confidence >= 0.75:
            confidence = min(confidence, 0.5)
        requires_human = (
            parsed.requires_human
            or signals.wants_human
            or signals.legal_threat
            or intent.always_escalate
        )
        sentiment = parsed.sentiment
        if signals.sentiment is Sentiment.VERY_NEGATIVE:
            sentiment = Sentiment.VERY_NEGATIVE
        return Classification(
            intent=intent,
            priority=priority,
            sentiment=sentiment,
            confidence=round(confidence, 3),
            requires_tool=parsed.requires_tool or bool(references),
            requires_human=requires_human,
            language=parsed.language,
            summary=truncate(parsed.summary, 300),
            source="llm",
            references=references,
            degraded=degraded,
        )

    def _from_rules(
        self,
        rules: RuleClassification,
        signals: MessageSignals,
        *,
        source: Literal["rules", "rules_fallback"],
        degraded: bool,
    ) -> Classification:
        return Classification(
            intent=rules.intent,
            priority=rules.priority,
            sentiment=signals.sentiment,
            confidence=rules.confidence,
            requires_tool=rules.requires_tool,
            requires_human=rules.requires_human,
            language="en",
            summary=f"Customer request classified as {rules.intent.name.replace('_', ' ')}.",
            source=source,
            references={k: list(v) for k, v in signals.references.items()},
            degraded=degraded,
        )
