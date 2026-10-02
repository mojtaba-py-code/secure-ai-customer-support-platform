"""Deterministic turn policy: risk evaluation, human handoff and least-privilege tool selection.

The agent never decides *on its own* whether a situation is high-risk. This module does, in
code, from the classification plus deterministic signals and conversation history:

    classification + signals + injection risk + history
        -> escalate | clarify | proceed (with an allow-list of tools and knowledge categories)

Tool allow-lists are the intersection of (tools the intent needs) and (tools the caller's role
may use); a turn flagged as a possible prompt injection additionally loses every tool that can
change anything, so a successful injection can at most *read* the customer's own data.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

from aegis.agents.classifier import Classification
from aegis.agents.intents import FALLBACK_INTENT
from aegis.agents.signals import MessageSignals
from aegis.domain.enums import HandoffReason, KnowledgeCategory, Priority, Sentiment
from aegis.security.injection import InjectionAssessment, RiskLevel
from aegis.security.principal import Principal
from aegis.tools.base import SideEffect
from aegis.tools.registry import ToolRegistry


@dataclass(frozen=True, slots=True)
class PolicySettings:
    min_confidence: float
    suspicious_threshold: int
    failure_threshold: int


@dataclass(frozen=True, slots=True)
class ConversationRisk:
    suspicious_count: int
    ai_failure_count: int
    clarification_pending: bool


@dataclass(frozen=True, slots=True)
class TurnDecision:
    action: Literal["proceed", "clarify", "escalate", "refuse"]
    priority: Priority
    handoff_reason: HandoffReason | None = None
    allowed_tools: frozenset[str] = frozenset()
    knowledge_categories: tuple[KnowledgeCategory, ...] = ()
    restrict_writes: bool = False
    notes: tuple[str, ...] = ()


class TurnPolicy:
    def __init__(self, tools: ToolRegistry, settings: PolicySettings) -> None:
        self._tools = tools
        self._settings = settings
        self._write_tools = tools.with_side_effects(SideEffect.WRITE, SideEffect.PROPOSE)

    def decide(  # noqa: PLR0911 - an explicit, ordered decision table reads best as early returns
        self,
        *,
        principal: Principal,
        classification: Classification,
        signals: MessageSignals,
        injection: InjectionAssessment,
        risk: ConversationRisk,
    ) -> TurnDecision:
        intent = classification.intent
        priority = classification.priority

        def escalate(reason: HandoffReason, minimum: Priority) -> TurnDecision:
            return TurnDecision(
                action="escalate",
                priority=Priority.highest(priority, minimum),
                handoff_reason=reason,
            )

        if signals.account_compromise or intent.always_escalate:
            return escalate(
                intent.escalation_reason or HandoffReason.ACCOUNT_SECURITY, Priority.URGENT
            )
        if signals.legal_threat:
            return escalate(HandoffReason.LEGAL, Priority.HIGH)
        if signals.wants_human:
            return escalate(HandoffReason.CUSTOMER_REQUEST, Priority.MEDIUM)
        if (
            injection.level is RiskLevel.HIGH
            and risk.suspicious_count >= self._settings.suspicious_threshold
        ):
            return escalate(HandoffReason.SUSPICIOUS_ACTIVITY, Priority.HIGH)
        if risk.ai_failure_count >= self._settings.failure_threshold:
            return escalate(HandoffReason.REPEATED_FAILURE, Priority.HIGH)
        if classification.requires_human:
            return escalate(HandoffReason.UNSUPPORTED_REQUEST, Priority.MEDIUM)
        if classification.sentiment is Sentiment.VERY_NEGATIVE and intent.name == "complaint":
            return escalate(HandoffReason.NEGATIVE_SENTIMENT, Priority.HIGH)
        if (
            injection.level is RiskLevel.HIGH
            and intent.name == FALLBACK_INTENT
            and not signals.references
        ):
            # A manipulation attempt with no genuine support request: decline without calling the model.
            return TurnDecision(action="refuse", priority=priority)
        if classification.confidence < self._settings.min_confidence:
            if risk.clarification_pending:
                return escalate(HandoffReason.LOW_CONFIDENCE, Priority.MEDIUM)
            return TurnDecision(action="clarify", priority=priority)

        permitted = {
            name
            for name in intent.tools
            if (definition := self._tools.get(name)) is not None
            and principal.has(definition.permission)
        }
        notes: list[str] = []
        restrict = injection.level.rank >= RiskLevel.MEDIUM.rank
        if restrict:
            permitted -= self._write_tools
            notes.append(
                "write actions are disabled for this message; offer a human agent for changes"
            )
        return TurnDecision(
            action="proceed",
            priority=priority,
            allowed_tools=frozenset(permitted),
            knowledge_categories=intent.knowledge,
            restrict_writes=restrict,
            notes=tuple(notes),
        )
