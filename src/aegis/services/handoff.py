"""Human handoff: escalation into the staff queue and the agent-desk workflow.

Once a conversation is escalated the AI stops answering in it; customer messages are stored for
the human agent. Escalation is idempotent (repeated triggers reuse the open ticket and only raise
the priority), and every queue operation is permission-checked and audited.
"""

from __future__ import annotations

import uuid

from sqlalchemy.ext.asyncio import AsyncSession

from aegis.core.errors import Conflict, NotFound, PermissionDenied, ValidationFailed
from aegis.core.ids import reference_number
from aegis.core.time import Clock, utc_now
from aegis.domain.enums import (
    HUMAN_HANDLED_STATUSES,
    STAFF_ROLES,
    AuditOutcome,
    ConversationStatus,
    HandoffReason,
    Priority,
    RequestSource,
    SenderType,
    TicketStatus,
)
from aegis.models import Conversation, Message, SupportTicket
from aegis.observability import metrics
from aegis.repositories.identity import UserRepository
from aegis.repositories.support import ConversationRepository, TicketRepository
from aegis.security.principal import Principal
from aegis.security.rbac import Permission
from aegis.security.redaction import redact_for_storage
from aegis.security.text import normalize_text, truncate
from aegis.services.audit import AuditService
from aegis.services.authz import require

MAX_AGENT_REPLY = 4_000


class HandoffService:
    def __init__(
        self, session: AsyncSession, *, audit: AuditService, clock: Clock = utc_now
    ) -> None:
        self._session = session
        self._conversations = ConversationRepository(session)
        self._tickets = TicketRepository(session)
        self._users = UserRepository(session)
        self._audit = audit
        self._clock = clock

    async def escalate(
        self,
        conversation: Conversation,
        *,
        reason: HandoffReason,
        priority: Priority,
        summary: str,
        category: str,
    ) -> SupportTicket:
        """Move a conversation to the human queue (idempotent) and commit."""
        now = self._clock()
        already = conversation.status in HUMAN_HANDLED_STATUSES
        if not already:
            conversation.status = ConversationStatus.AWAITING_AGENT
            conversation.escalated_at = now
            conversation.escalation_reason = reason
        current = conversation.escalation_priority
        conversation.escalation_priority = (
            Priority.highest(priority, current) if current else priority
        )

        ticket = await self._tickets.open_ticket_for_conversation(conversation.id)
        if ticket is None:
            ticket = self._tickets.add(
                SupportTicket(
                    ticket_number=reference_number("TCK"),
                    customer_id=conversation.customer_id,
                    conversation_id=conversation.id,
                    created_by_user_id=None,
                    subject=f"Escalated conversation: {reason.value.replace('_', ' ')}",
                    description=truncate(redact_for_storage(normalize_text(summary)).text, 2_000)
                    or "Escalated by the assistant.",
                    category=category[:40],
                    priority=conversation.escalation_priority or priority,
                    status=TicketStatus.OPEN,
                    source=RequestSource.ESCALATION,
                    idempotency_key=f"escalation:{conversation.id}:{now:%Y%m%d%H%M%S}",
                )
            )
        else:
            ticket.priority = Priority.highest(ticket.priority, priority)
        await self._session.commit()
        if not already:
            metrics.ESCALATIONS.labels(reason=reason.value).inc()
            await self._audit.record(
                "handoff.escalate",
                outcome=AuditOutcome.SUCCESS,
                actor_user_id=conversation.user_id,
                actor_role="customer",
                resource_type="conversation",
                resource_id=conversation.id,
                details={
                    "reason": reason.value,
                    "priority": priority.value,
                    "ticket": ticket.ticket_number,
                },
            )
        return ticket

    async def queue(
        self,
        principal: Principal,
        *,
        status: ConversationStatus | None,
        priority: Priority | None,
        mine: bool,
        limit: int,
        offset: int,
    ) -> list[Conversation]:
        require(principal, Permission.HANDOFF_QUEUE_READ)
        statuses = [status] if status is not None else list(HUMAN_HANDLED_STATUSES)
        return await self._conversations.queue(
            statuses=statuses,
            priority=priority,
            assigned_to=principal.user_id if mine else None,
            limit=limit,
            offset=offset,
        )

    async def _locked(self, conversation_id: uuid.UUID) -> Conversation:
        conversation = await self._conversations.get_for_update(conversation_id)
        if conversation is None:
            raise NotFound
        return conversation

    def _ensure_handler(self, principal: Principal, conversation: Conversation) -> None:
        if conversation.assigned_agent_id == principal.user_id:
            return
        if principal.has(Permission.HANDOFF_ASSIGN_ANY):
            return
        raise PermissionDenied("This conversation is assigned to another agent.")

    async def claim(self, principal: Principal, conversation_id: uuid.UUID) -> Conversation:
        require(principal, Permission.HANDOFF_CLAIM)
        conversation = await self._locked(conversation_id)
        if conversation.status not in HUMAN_HANDLED_STATUSES:
            raise Conflict("This conversation is not waiting for a human agent.")
        if conversation.assigned_agent_id not in (None, principal.user_id):
            require(principal, Permission.HANDOFF_ASSIGN_ANY)
        return await self._assign(principal, conversation, principal.user_id)

    async def assign(
        self, principal: Principal, conversation_id: uuid.UUID, agent_user_id: uuid.UUID
    ) -> Conversation:
        require(principal, Permission.HANDOFF_ASSIGN_ANY)
        agent = await self._users.get(agent_user_id)
        if agent is None or not agent.is_active or agent.role not in STAFF_ROLES:
            raise ValidationFailed("Conversations can only be assigned to active staff members.")
        conversation = await self._locked(conversation_id)
        if conversation.status not in HUMAN_HANDLED_STATUSES:
            raise Conflict("This conversation is not waiting for a human agent.")
        return await self._assign(principal, conversation, agent_user_id)

    async def _assign(
        self, principal: Principal, conversation: Conversation, agent_id: uuid.UUID
    ) -> Conversation:
        conversation.assigned_agent_id = agent_id
        conversation.status = ConversationStatus.AGENT_ASSIGNED
        ticket = await self._tickets.open_ticket_for_conversation(conversation.id)
        if ticket is not None:
            ticket.assigned_to_user_id = agent_id
            ticket.status = TicketStatus.IN_PROGRESS
        await self._session.commit()
        await self._audit.record(
            "handoff.assign",
            outcome=AuditOutcome.SUCCESS,
            actor=principal,
            resource_type="conversation",
            resource_id=conversation.id,
            details={"agent": str(agent_id)},
        )
        return conversation

    async def reply(
        self, principal: Principal, conversation_id: uuid.UUID, content: str
    ) -> Message:
        require(principal, Permission.HANDOFF_REPLY)
        text = truncate(redact_for_storage(normalize_text(content)).text, MAX_AGENT_REPLY)
        if not text:
            raise ValidationFailed("The reply is empty.")
        conversation = await self._locked(conversation_id)
        if conversation.status is not ConversationStatus.AGENT_ASSIGNED:
            raise Conflict("Claim the conversation before replying.")
        self._ensure_handler(principal, conversation)
        message = await self._conversations.append_message(
            conversation,
            sender_type=SenderType.AGENT,
            content=text,
            now=self._clock(),
            sender_user_id=principal.user_id,
            meta={"agent_display_name": principal.display_name[:60]},
        )
        await self._session.commit()
        await self._audit.record(
            "handoff.reply",
            outcome=AuditOutcome.SUCCESS,
            actor=principal,
            resource_type="conversation",
            resource_id=conversation.id,
        )
        return message

    async def resolve(
        self, principal: Principal, conversation_id: uuid.UUID, *, return_to_ai: bool
    ) -> Conversation:
        require(principal, Permission.HANDOFF_RESOLVE)
        conversation = await self._locked(conversation_id)
        if conversation.status not in HUMAN_HANDLED_STATUSES:
            raise Conflict("This conversation is not being handled by a human agent.")
        self._ensure_handler(principal, conversation)
        now = self._clock()
        conversation.status = (
            ConversationStatus.ACTIVE if return_to_ai else ConversationStatus.RESOLVED
        )
        conversation.assigned_agent_id = None if return_to_ai else conversation.assigned_agent_id
        conversation.ai_failure_count = 0
        conversation.suspicious_count = 0
        if not return_to_ai:
            conversation.closed_at = now
        ticket = await self._tickets.open_ticket_for_conversation(conversation.id)
        if ticket is not None:
            ticket.status = TicketStatus.RESOLVED
            ticket.resolved_at = now
        await self._session.commit()
        await self._audit.record(
            "handoff.resolve",
            outcome=AuditOutcome.SUCCESS,
            actor=principal,
            resource_type="conversation",
            resource_id=conversation.id,
            details={"return_to_ai": return_to_ai},
        )
        return conversation
