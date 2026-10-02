"""The support agent: one customer message in, one validated reply out.

    customer message
      -> normalise, length-check, injection screening, PII redaction (storage view / model view)
      -> persist (encrypted)                         -> human-handled? stop, the specialist replies
      -> classify (structured output, validated; rules fallback)
      -> policy: escalate | clarify | proceed(tool allow-list, knowledge categories)
      -> retrieve knowledge (visibility-filtered, validated, budgeted)
      -> tool loop (bounded iterations and calls; every call through the executor)
      -> output guard (leaks, secrets, grounding, links, PII) -> one corrective retry at most
      -> persist reply + metadata, escalate if requested, update memory, metrics, audit

Everything runs under a per-conversation distributed lock and an overall deadline. Any failure
produces a safe reply; repeated failures hand the conversation to a human.
"""

from __future__ import annotations

import asyncio
import logging
import uuid
from dataclasses import dataclass
from typing import Any, Protocol

from aegis.agents.classifier import Classification, IntentClassifier
from aegis.agents.guard import GuardResult, OutputGuard, cited_indices
from aegis.agents.memory import ConversationMemory, ConversationState, ConversationStateStore
from aegis.agents.policy import ConversationRisk, TurnDecision, TurnPolicy
from aegis.agents.prompts import render_correction, render_user_turn
from aegis.agents.responses import (
    CANNOT_HELP,
    CLARIFY,
    SENSITIVE_DATA_WARNING,
    UNAVAILABLE,
    UNVERIFIED,
    handoff_reply,
)
from aegis.agents.signals import MessageSignals, detect_signals
from aegis.core.errors import Conflict, DependencyUnavailable, PermissionDenied, ValidationFailed
from aegis.core.time import utc_today
from aegis.domain.enums import (
    HUMAN_HANDLED_STATUSES,
    AuditOutcome,
    ConversationStatus,
    HandoffReason,
    KnowledgeVisibility,
    Priority,
    SenderType,
)
from aegis.kv.base import KeyBuilder, KeyValueStore
from aegis.kv.locks import distributed_lock
from aegis.llm.gateway import LLMGateway
from aegis.llm.types import ChatMessage, ContextDocument, LLMRequest, LLMTask, StopReason, ToolSpec
from aegis.models import Conversation, Message
from aegis.observability import metrics
from aegis.rag.retriever import KnowledgeRetriever
from aegis.security.crypto import fingerprint
from aegis.security.injection import InjectionAssessment, PromptInjectionDetector
from aegis.security.principal import Principal
from aegis.security.rbac import Permission
from aegis.security.redaction import (
    STORAGE_FORBIDDEN_KINDS,
    RedactionResult,
    redact_for_llm,
    redact_for_storage,
)
from aegis.security.text import normalize_text
from aegis.services.audit import AuditService
from aegis.services.conversations import ConversationService
from aegis.services.handoff import HandoffService
from aegis.tools.base import ProposedAction, ToolContext, ToolServices, TurnToolState
from aegis.tools.executor import ToolExecutor
from aegis.tools.registry import ToolRegistry

logger = logging.getLogger(__name__)


class AgentServices(Protocol):
    @property
    def conversations(self) -> ConversationService: ...

    @property
    def handoff(self) -> HandoffService: ...

    @property
    def tools(self) -> ToolServices: ...


@dataclass(frozen=True, slots=True)
class AgentSettings:
    max_iterations: int
    turn_timeout_seconds: float
    max_message_chars: int
    agent_max_tokens: int
    failure_threshold: int


@dataclass(frozen=True, slots=True)
class Citation:
    index: int
    title: str
    section: str
    source_id: str


@dataclass(frozen=True, slots=True)
class TurnResult:
    conversation_id: uuid.UUID
    status: ConversationStatus
    customer_message: Message
    reply: Message | None
    intent: str | None = None
    confidence: float | None = None
    escalated: bool = False
    ticket_number: str | None = None
    citations: tuple[Citation, ...] = ()
    actions: tuple[ProposedAction, ...] = ()
    degraded: bool = False


@dataclass(slots=True)
class _LoopOutcome:
    text: str | None
    raw: Any = None
    degraded: bool = False
    refused: bool = False
    truncated: bool = False
    exhausted: bool = False


@dataclass(frozen=True, slots=True)
class _Screened:
    text: str
    stored: RedactionResult
    for_model: RedactionResult
    signals: MessageSignals
    injection: InjectionAssessment


@dataclass(slots=True)
class _Turn:
    """Everything one answered turn needs, passed as a unit between its steps."""

    principal: Principal
    conversation: Conversation
    customer_message: Message
    screened: _Screened
    classification: Classification
    decision: TurnDecision
    services: AgentServices
    base_meta: dict[str, Any]
    state: ConversationState


@dataclass(frozen=True, slots=True)
class _LoopSetup:
    tool_specs: tuple[ToolSpec, ...]
    ctx: ToolContext
    allowed: frozenset[str]
    metadata: dict[str, Any]


def visibility_for(principal: Principal) -> frozenset[KnowledgeVisibility]:
    if principal.has(Permission.KB_READ_INTERNAL):
        return frozenset({KnowledgeVisibility.PUBLIC, KnowledgeVisibility.INTERNAL})
    if principal.has(Permission.KB_READ_PUBLIC):
        return frozenset({KnowledgeVisibility.PUBLIC})
    return frozenset()


class SupportAgent:
    def __init__(
        self,
        *,
        gateway: LLMGateway,
        classifier: IntentClassifier,
        policy: TurnPolicy,
        retriever: KnowledgeRetriever,
        tools: ToolRegistry,
        executor: ToolExecutor,
        guard: OutputGuard,
        memory: ConversationMemory,
        state_store: ConversationStateStore,
        detector: PromptInjectionDetector,
        audit: AuditService,
        kv: KeyValueStore,
        keys: KeyBuilder,
        system_prompt: str,
        settings: AgentSettings,
    ) -> None:
        self._gateway = gateway
        self._classifier = classifier
        self._policy = policy
        self._retriever = retriever
        self._tools = tools
        self._executor = executor
        self._guard = guard
        self._memory = memory
        self._state_store = state_store
        self._detector = detector
        self._audit = audit
        self._kv = kv
        self._keys = keys
        self._system_prompt = system_prompt
        self._settings = settings

    # ---------------------------------------------------------------------------------------------
    async def handle_message(
        self, principal: Principal, conversation_id: uuid.UUID, text: str, services: AgentServices
    ) -> TurnResult:
        if not principal.has(Permission.MESSAGE_SEND):
            raise PermissionDenied
        clean = normalize_text(text)
        if not clean:
            raise ValidationFailed("The message is empty.")
        if len(clean) > self._settings.max_message_chars:
            raise ValidationFailed(
                f"Messages are limited to {self._settings.max_message_chars} characters."
            )
        lock_key = self._keys.key("lock", "conversation", str(conversation_id))
        ttl = int(self._settings.turn_timeout_seconds) + 30
        async with distributed_lock(self._kv, lock_key, ttl_seconds=ttl):
            return await self._handle_locked(principal, conversation_id, clean, services)

    async def _handle_locked(
        self, principal: Principal, conversation_id: uuid.UUID, text: str, services: AgentServices
    ) -> TurnResult:
        conversations = services.conversations
        conversation = await conversations.lock_owned(principal, conversation_id)
        if conversation.status in (ConversationStatus.CLOSED, ConversationStatus.RESOLVED):
            raise Conflict("This conversation is closed. Please start a new conversation.")

        screened = self._screen(text)
        customer_message = await conversations.append(
            conversation,
            sender_type=SenderType.CUSTOMER,
            content=screened.stored.text,
            sender_user_id=principal.user_id,
            meta={
                "injection_level": screened.injection.level.value,
                "redacted": sorted(screened.stored.counts),
            },
        )
        if screened.injection.is_suspicious:
            conversation.suspicious_count += 1
        await conversations.commit()
        if screened.injection.is_suspicious:
            metrics.security_event("prompt_injection_suspected")
            await self._audit.record(
                "agent.injection_suspected",
                outcome=AuditOutcome.DENIED,
                actor=principal,
                resource_type="conversation",
                resource_id=conversation.id,
                details={
                    "level": screened.injection.level.value,
                    "categories": list(screened.injection.categories),
                },
            )

        if conversation.status in HUMAN_HANDLED_STATUSES:
            signals = screened.signals
            if signals.account_compromise or signals.legal_threat:
                # Already with a human: make sure the queue reflects the new severity.
                await services.handoff.escalate(
                    conversation,
                    reason=HandoffReason.ACCOUNT_SECURITY
                    if signals.account_compromise
                    else HandoffReason.LEGAL,
                    priority=Priority.URGENT if signals.account_compromise else Priority.HIGH,
                    summary="The customer reported a security or legal issue while waiting for an agent.",
                    category="security_problem" if signals.account_compromise else "complaint",
                )
            return TurnResult(
                conversation_id=conversation.id,
                status=conversation.status,
                customer_message=customer_message,
                reply=None,
                escalated=True,
            )

        try:
            async with asyncio.timeout(self._settings.turn_timeout_seconds):
                return await self._run_turn(
                    principal, conversation, customer_message, screened, services
                )
        except Exception as exc:  # every failure still produces a safe reply
            logger.exception(
                "agent turn failed",
                extra={"event": "agent.turn_failed", "error_type": type(exc).__name__},
            )
            return await self._fail_turn(principal, conversation.id, customer_message, services)

    def _screen(self, text: str) -> _Screened:
        return _Screened(
            text=text,
            stored=redact_for_storage(text),
            for_model=redact_for_llm(text),
            signals=detect_signals(text),
            injection=self._detector.assess(text),
        )

    # ---------------------------------------------------------------------------------------------
    async def _run_turn(
        self,
        principal: Principal,
        conversation: Conversation,
        customer_message: Message,
        screened: _Screened,
        services: AgentServices,
    ) -> TurnResult:
        state = await self._state_store.get(conversation.id)
        user_ref = fingerprint(str(principal.user_id))
        classification = await self._classifier.classify(
            screened.for_model.text,
            signals=screened.signals,
            previous_intent=state.last_intent,
            user_id=principal.user_id,
            conversation_id=conversation.id,
            user_ref=user_ref,
        )
        decision = self._policy.decide(
            principal=principal,
            classification=classification,
            signals=screened.signals,
            injection=screened.injection,
            risk=ConversationRisk(
                suspicious_count=conversation.suspicious_count,
                ai_failure_count=conversation.ai_failure_count,
                clarification_pending=state.clarification_pending,
            ),
        )
        base_meta: dict[str, Any] = {
            "intent": classification.intent.name,
            "confidence": classification.confidence,
            "priority": decision.priority.value,
            "sentiment": classification.sentiment.value,
            "classifier": classification.source,
        }

        if decision.action == "escalate" and decision.handoff_reason is not None:
            return await self._escalate_turn(
                principal,
                conversation,
                customer_message,
                classification,
                decision,
                services,
                base_meta,
                state,
            )
        if decision.action == "refuse":
            reply = await self._store_reply(
                services,
                conversation,
                CANNOT_HELP,
                {**base_meta, "refused": True},
                reset_failures=True,
            )
            await self._state_store.save(
                conversation.id,
                ConversationState(
                    last_intent=state.last_intent,
                    clarification_pending=False,
                    turns=state.turns + 1,
                ),
            )
            metrics.AGENT_TURNS.labels(intent=classification.intent.name, outcome="refused").inc()
            return TurnResult(
                conversation_id=conversation.id,
                status=conversation.status,
                customer_message=customer_message,
                reply=reply,
                intent=classification.intent.name,
                confidence=classification.confidence,
                degraded=classification.degraded,
            )
        if decision.action == "clarify":
            reply = await self._store_reply(
                services,
                conversation,
                CLARIFY,
                {**base_meta, "clarification": True},
                reset_failures=True,
            )
            await self._state_store.save(
                conversation.id,
                ConversationState(
                    last_intent=state.last_intent, clarification_pending=True, turns=state.turns + 1
                ),
            )
            metrics.AGENT_TURNS.labels(intent=classification.intent.name, outcome="clarify").inc()
            return TurnResult(
                conversation_id=conversation.id,
                status=conversation.status,
                customer_message=customer_message,
                reply=reply,
                intent=classification.intent.name,
                confidence=classification.confidence,
                degraded=classification.degraded,
            )
        return await self._answer_turn(
            _Turn(
                principal=principal,
                conversation=conversation,
                customer_message=customer_message,
                screened=screened,
                classification=classification,
                decision=decision,
                services=services,
                base_meta=base_meta,
                state=state,
            )
        )

    async def _escalate_turn(
        self,
        principal: Principal,
        conversation: Conversation,
        customer_message: Message,
        classification: Classification,
        decision: TurnDecision,
        services: AgentServices,
        base_meta: dict[str, Any],
        state: ConversationState,
    ) -> TurnResult:
        reason = decision.handoff_reason or HandoffReason.UNSUPPORTED_REQUEST
        conversation = await services.conversations.lock_owned(principal, conversation.id)
        ticket = await services.handoff.escalate(
            conversation,
            reason=reason,
            priority=decision.priority,
            summary=classification.summary,
            category=classification.intent.name,
        )
        conversation = await services.conversations.lock_owned(principal, conversation.id)
        reply = await services.conversations.append(
            conversation,
            sender_type=SenderType.ASSISTANT,
            content=handoff_reply(reason, ticket.ticket_number),
            meta={
                **base_meta,
                "escalated": True,
                "handoff_reason": reason.value,
                "ticket": ticket.ticket_number,
            },
        )
        await services.conversations.commit()
        await self._state_store.save(
            conversation.id,
            ConversationState(
                last_intent=classification.intent.name,
                clarification_pending=False,
                turns=state.turns + 1,
            ),
        )
        metrics.AGENT_TURNS.labels(intent=classification.intent.name, outcome="escalated").inc()
        return TurnResult(
            conversation_id=conversation.id,
            status=conversation.status,
            customer_message=customer_message,
            reply=reply,
            intent=classification.intent.name,
            confidence=classification.confidence,
            escalated=True,
            ticket_number=ticket.ticket_number,
            degraded=classification.degraded,
        )

    async def _answer_turn(self, turn: _Turn) -> TurnResult:
        notes = list(turn.decision.notes)
        documents = await self._retrieve(turn, notes)
        shared_sensitive = bool(
            set(turn.screened.stored.counts) & {k.value for k in STORAGE_FORBIDDEN_KINDS}
        )
        if shared_sensitive:
            notes.append(
                "the customer shared sensitive data that was removed; remind them not to share it"
            )
        tool_state = TurnToolState()
        outcome, guard = await self._generate(turn, documents, notes, tool_state)

        reply_text, failed = self._final_text(outcome, guard, tool_state)
        if shared_sensitive and SENSITIVE_DATA_WARNING not in reply_text:
            reply_text = f"{SENSITIVE_DATA_WARNING}\n\n{reply_text}"
        if guard is not None:
            for kind in guard.violations:
                metrics.GUARD_VIOLATIONS.labels(kind=kind).inc()
            if guard.blocked and "system_prompt_leak" in guard.violations:
                metrics.security_event("prompt_leak_blocked")
        citations = tuple(
            Citation(
                index=i,
                title=documents[i - 1].title,
                section=documents[i - 1].section,
                source_id=documents[i - 1].source_id,
            )
            for i in cited_indices(reply_text, len(documents))
        )
        meta = {
            **turn.base_meta,
            "citations": [_citation_dict(c) for c in citations],
            "tools": tool_state.tools_used,
            "actions": [a.action_id for a in tool_state.proposed_actions],
            "degraded": outcome.degraded or turn.classification.degraded,
            "guard": list(guard.violations) if guard else [],
            "fallback": failed,
        }
        leaked = (
            guard is not None
            and guard.blocked
            and any(v.endswith("_leak") for v in guard.violations)
        )
        reply, ticket_number, conversation = await self._persist_answer(
            turn, reply_text, meta, tool_state, failed=failed, leaked=leaked
        )
        await self._state_store.save(
            conversation.id,
            ConversationState(
                last_intent=turn.classification.intent.name,
                clarification_pending=False,
                turns=turn.state.turns + 1,
            ),
        )
        await self._maybe_summarize(turn.services.conversations, conversation)
        outcome_label = "escalated" if ticket_number else ("fallback" if failed else "answered")
        metrics.AGENT_TURNS.labels(
            intent=turn.classification.intent.name, outcome=outcome_label
        ).inc()
        await self._audit.record(
            "agent.turn",
            outcome=AuditOutcome.SUCCESS if not failed else AuditOutcome.FAILURE,
            actor=turn.principal,
            resource_type="conversation",
            resource_id=conversation.id,
            details={
                "intent": turn.classification.intent.name,
                "tools": tool_state.tools_used,
                "escalated": bool(ticket_number),
                "degraded": meta["degraded"],
                "guard": meta["guard"],
            },
        )
        return TurnResult(
            conversation_id=conversation.id,
            status=conversation.status,
            customer_message=turn.customer_message,
            reply=reply,
            intent=turn.classification.intent.name,
            confidence=turn.classification.confidence,
            escalated=bool(ticket_number),
            ticket_number=ticket_number,
            citations=citations,
            actions=tuple(tool_state.proposed_actions),
            degraded=bool(meta["degraded"]),
        )

    async def _retrieve(self, turn: _Turn, notes: list[str]) -> list[ContextDocument]:
        if not turn.decision.knowledge_categories:
            return []
        try:
            chunks = await self._retriever.retrieve(
                turn.screened.for_model.text,
                visibilities=visibility_for(turn.principal),
                categories=turn.decision.knowledge_categories,
            )
        except DependencyUnavailable:
            notes.append(
                "the knowledge base is temporarily unavailable; do not answer policy questions from memory"
            )
            return []
        return [
            ContextDocument(
                index=i,
                source_id=c.source_id,
                document_id=c.document_id,
                title=c.title,
                section=c.section,
                text=c.text,
                score=c.score,
                category=c.category,
            )
            for i, c in enumerate(chunks, start=1)
        ]

    async def _generate(
        self,
        turn: _Turn,
        documents: list[ContextDocument],
        notes: list[str],
        tool_state: TurnToolState,
    ) -> tuple[_LoopOutcome, GuardResult | None]:
        """Run the tool loop, validate the reply, and allow one corrective regeneration."""
        summary, history = await self._memory.history(
            turn.services.conversations,
            turn.conversation,
            before_sequence=turn.customer_message.sequence,
        )
        classification = turn.classification
        user_turn = ChatMessage(
            role="user",
            text=render_user_turn(
                customer_text=turn.screened.for_model.text,
                documents=documents,
                today=utc_today().isoformat(),
                intent=classification.intent.name,
                references=[ref for values in classification.references.values() for ref in values],
                notes=notes,
                include_knowledge=bool(turn.decision.knowledge_categories),
                summary=summary,
            ),
            documents=tuple(documents),
        )
        messages: list[ChatMessage] = [*history, user_turn]
        loop = _LoopSetup(
            tool_specs=self._tools.specs(turn.decision.allowed_tools),
            ctx=ToolContext(
                principal=turn.principal,
                conversation_id=turn.conversation.id,
                message_id=turn.customer_message.id,
                intent=classification.intent.name,
                priority=turn.decision.priority,
                services=turn.services.tools,
                state=tool_state,
            ),
            allowed=turn.decision.allowed_tools,
            metadata={
                "intent": classification.intent.name,
                "references": classification.references,
                "customer_text": turn.screened.for_model.text,
                "user_ref": fingerprint(str(turn.principal.user_id)),
                "notes": notes,
            },
        )
        outcome = await self._loop(messages, loop, turn, self._settings.max_iterations)
        evidence = [
            *tool_state.evidence,
            *(d.text for d in documents),
            turn.screened.for_model.text,
            *(m.text for m in history),
            summary or "",
        ]
        guard = self._validate(outcome, evidence, len(documents))
        if guard is None or not guard.retryable or guard.blocked or not outcome.text:
            return outcome, guard
        messages.append(ChatMessage(role="assistant", text=outcome.text, provider_raw=outcome.raw))
        messages.append(ChatMessage(role="user", text=render_correction(guard.ungrounded)))
        retry = await self._loop(messages, loop, turn, 2)
        outcome.degraded = outcome.degraded or retry.degraded
        retried = self._validate(retry, [*evidence, *tool_state.evidence], len(documents))
        if retried is None or retried.retryable:
            metrics.GUARD_VIOLATIONS.labels(kind="ungrounded_after_retry").inc()
            return outcome, None
        return outcome, retried

    async def _persist_answer(
        self,
        turn: _Turn,
        reply_text: str,
        meta: dict[str, Any],
        tool_state: TurnToolState,
        *,
        failed: bool,
        leaked: bool,
    ) -> tuple[Message, str | None, Conversation]:
        services = turn.services
        conversation = await services.conversations.lock_owned(turn.principal, turn.conversation.id)
        if leaked:
            conversation.suspicious_count += 1
        handoff: tuple[HandoffReason, str] | None = None
        if tool_state.escalation is not None:
            handoff = (tool_state.escalation.reason, tool_state.escalation.summary)
        elif failed:
            conversation.ai_failure_count += 1
            if conversation.ai_failure_count >= self._settings.failure_threshold:
                handoff = (
                    HandoffReason.REPEATED_FAILURE,
                    "The assistant could not answer the customer's request after repeated attempts.",
                )
        if handoff is None:
            reply = await self._store_reply(
                services, conversation, reply_text, meta, reset_failures=not failed
            )
            return reply, None, conversation
        reason, summary = handoff
        ticket = await services.handoff.escalate(
            conversation,
            reason=reason,
            priority=Priority.highest(turn.decision.priority, Priority.MEDIUM),
            summary=summary,
            category=turn.classification.intent.name,
        )
        conversation = await services.conversations.lock_owned(turn.principal, conversation.id)
        handoff_text = handoff_reply(reason, ticket.ticket_number)
        text = f"{reply_text}\n\n{handoff_text}".strip() if tool_state.escalation else handoff_text
        reply = await services.conversations.append(
            conversation,
            sender_type=SenderType.ASSISTANT,
            content=text,
            meta={
                **meta,
                "escalated": True,
                "ticket": ticket.ticket_number,
                "handoff_reason": reason.value,
            },
        )
        await services.conversations.commit()
        return reply, ticket.ticket_number, conversation

    # ---------------------------------------------------------------------------------------------
    async def _loop(
        self,
        messages: list[ChatMessage],
        setup: _LoopSetup,
        turn: _Turn,
        max_iterations: int,
    ) -> _LoopOutcome:
        degraded = False
        ctx, allowed = setup.ctx, setup.allowed
        for _iteration in range(max_iterations):
            response = await self._gateway.complete(
                LLMRequest(
                    task=LLMTask.AGENT,
                    system=self._system_prompt,
                    messages=list(messages),
                    tools=setup.tool_specs,
                    max_output_tokens=self._settings.agent_max_tokens,
                    metadata=setup.metadata,
                ),
                user_id=turn.principal.user_id,
                conversation_id=turn.conversation.id,
            )
            degraded = degraded or response.degraded
            if response.stop_reason is StopReason.REFUSAL:
                return _LoopOutcome(None, degraded=degraded, refused=True)
            if response.stop_reason is StopReason.MAX_TOKENS:
                return _LoopOutcome(None, degraded=degraded, truncated=True)
            if response.tool_calls:
                messages.append(
                    ChatMessage(
                        role="assistant",
                        text=response.text,
                        tool_calls=response.tool_calls,
                        provider_raw=response.raw_content,
                    )
                )
                results = [
                    await self._executor.execute(call, ctx, allowed=allowed)
                    for call in response.tool_calls
                ]
                messages.append(ChatMessage(role="user", tool_results=tuple(results)))
                if ctx.state.escalation is not None:
                    return _LoopOutcome(
                        response.text or None, raw=response.raw_content, degraded=degraded
                    )
                continue
            return _LoopOutcome(response.text, raw=response.raw_content, degraded=degraded)
        return _LoopOutcome(None, degraded=degraded, exhausted=True)

    def _validate(
        self, outcome: _LoopOutcome, evidence: list[str], citation_count: int
    ) -> GuardResult | None:
        if outcome.text is None:
            return None
        return self._guard.check(outcome.text, evidence=evidence, citation_count=citation_count)

    @staticmethod
    def _final_text(
        outcome: _LoopOutcome, guard: GuardResult | None, state: TurnToolState
    ) -> tuple[str, bool]:
        """(reply text, whether the turn counts as an assistant failure)."""
        if state.escalation is not None:
            if guard is not None and not guard.blocked and not guard.retryable and guard.text:
                return guard.text, False
            return "", False
        if outcome.refused:
            return CANNOT_HELP, False
        if outcome.truncated or outcome.exhausted or outcome.text is None:
            return UNAVAILABLE, True
        if guard is None:
            return UNVERIFIED, True
        if guard.blocked:
            return CANNOT_HELP, False
        if guard.retryable:
            return UNVERIFIED, True
        return guard.text, False

    async def _store_reply(
        self,
        services: AgentServices,
        conversation: Conversation,
        text: str,
        meta: dict[str, Any],
        *,
        reset_failures: bool,
    ) -> Message:
        if reset_failures:
            conversation.ai_failure_count = 0
        reply = await services.conversations.append(
            conversation, sender_type=SenderType.ASSISTANT, content=text, meta=meta
        )
        await services.conversations.commit()
        return reply

    async def _maybe_summarize(
        self, conversations: ConversationService, conversation: Conversation
    ) -> None:
        try:
            await self._memory.maybe_summarize(conversations, conversation)
        except Exception:  # memory maintenance is best-effort
            logger.exception("conversation summary failed", extra={"event": "memory.summary_error"})
            await conversations.rollback()

    async def _fail_turn(
        self,
        principal: Principal,
        conversation_id: uuid.UUID,
        customer_message: Message,
        services: AgentServices,
    ) -> TurnResult:
        conversations = services.conversations
        await conversations.rollback()
        conversation = await conversations.lock_owned(principal, conversation_id)
        conversation.ai_failure_count += 1
        meta: dict[str, Any] = {"fallback": True, "error": "turn_failed"}
        ticket_number: str | None = None
        text = UNAVAILABLE
        if (
            conversation.ai_failure_count >= self._settings.failure_threshold
            and conversation.status not in HUMAN_HANDLED_STATUSES
        ):
            ticket = await services.handoff.escalate(
                conversation,
                reason=HandoffReason.AI_UNAVAILABLE,
                priority=Priority.HIGH,
                summary="The assistant could not complete the customer's request after repeated attempts.",
                category="general_question",
            )
            ticket_number = ticket.ticket_number
            conversation = await conversations.lock_owned(principal, conversation_id)
            text = handoff_reply(HandoffReason.AI_UNAVAILABLE, ticket_number)
            meta = {**meta, "escalated": True, "ticket": ticket_number}
        reply = await conversations.append(
            conversation, sender_type=SenderType.ASSISTANT, content=text, meta=meta
        )
        await conversations.commit()
        metrics.AGENT_TURNS.labels(intent="unknown", outcome="failed").inc()
        return TurnResult(
            conversation_id=conversation.id,
            status=conversation.status,
            customer_message=customer_message,
            reply=reply,
            escalated=ticket_number is not None,
            ticket_number=ticket_number,
        )


def _citation_dict(citation: Citation) -> dict[str, Any]:
    return {
        "index": citation.index,
        "title": citation.title,
        "section": citation.section,
        "source_id": citation.source_id,
    }
