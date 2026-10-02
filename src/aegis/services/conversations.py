"""Conversations and their messages (message text is encrypted at rest by the column type)."""

from __future__ import annotations

import uuid
from typing import Any

from sqlalchemy.ext.asyncio import AsyncSession

from aegis.core.errors import Conflict, NotFound, PermissionDenied
from aegis.core.time import Clock, utc_now
from aegis.domain.enums import AuditOutcome, ConversationStatus, SenderType
from aegis.models import Conversation, Message
from aegis.repositories.support import ConversationRepository
from aegis.security.principal import Principal
from aegis.security.rbac import Permission
from aegis.security.redaction import redact_for_storage
from aegis.security.text import normalize_text, truncate
from aegis.services.audit import AuditService
from aegis.services.authz import require


class ConversationService:
    def __init__(
        self, session: AsyncSession, *, audit: AuditService, clock: Clock = utc_now
    ) -> None:
        self._session = session
        self._repo = ConversationRepository(session)
        self._audit = audit
        self._clock = clock

    @property
    def session(self) -> AsyncSession:
        return self._session

    async def create(self, principal: Principal, *, subject: str | None) -> Conversation:
        require(principal, Permission.CONVERSATION_CREATE)
        if principal.customer_id is None:
            raise PermissionDenied
        now = self._clock()
        conversation = self._repo.add(
            Conversation(
                customer_id=principal.customer_id,
                user_id=principal.user_id,
                status=ConversationStatus.ACTIVE,
                # Plain column: payment data and secrets never reach it (same rule as messages).
                subject=truncate(redact_for_storage(normalize_text(subject)).text, 200)
                if subject
                else None,
                last_message_at=now,
                created_at=now,
                updated_at=now,
            )
        )
        await self._session.commit()
        return conversation

    async def get(self, principal: Principal, conversation_id: uuid.UUID) -> Conversation:
        if principal.has(Permission.CONVERSATION_READ_ANY):
            conversation = await self._repo.get(conversation_id)
        elif principal.has(Permission.CONVERSATION_READ_OWN):
            conversation = await self._repo.get_for_user(conversation_id, principal.user_id)
        else:
            raise PermissionDenied
        if conversation is None:
            raise NotFound
        return conversation

    async def list_own(
        self, principal: Principal, *, limit: int, offset: int
    ) -> list[Conversation]:
        require(principal, Permission.CONVERSATION_READ_OWN)
        return await self._repo.list_for_user(principal.user_id, limit=limit, offset=offset)

    async def messages(
        self,
        principal: Principal,
        conversation_id: uuid.UUID,
        *,
        before_sequence: int | None,
        limit: int,
    ) -> list[Message]:
        conversation = await self.get(principal, conversation_id)
        return await self._repo.messages_page(
            conversation.id, before_sequence=before_sequence, limit=limit
        )

    async def lock_owned(self, principal: Principal, conversation_id: uuid.UUID) -> Conversation:
        """Row-lock a conversation the caller owns (customer turn processing)."""
        conversation = await self._repo.get_for_update(conversation_id)
        if conversation is None or conversation.user_id != principal.user_id:
            raise NotFound
        return conversation

    async def append(
        self,
        conversation: Conversation,
        *,
        sender_type: SenderType,
        content: str,
        sender_user_id: uuid.UUID | None = None,
        meta: dict[str, Any] | None = None,
    ) -> Message:
        return await self._repo.append_message(
            conversation,
            sender_type=sender_type,
            content=content,
            now=self._clock(),
            sender_user_id=sender_user_id,
            meta=meta,
        )

    async def recent_messages(self, conversation_id: uuid.UUID, *, limit: int) -> list[Message]:
        return await self._repo.recent_messages(conversation_id, limit=limit)

    async def messages_in_range(
        self, conversation_id: uuid.UUID, *, after: int, through: int
    ) -> list[Message]:
        return await self._repo.messages_in_range(conversation_id, after=after, through=through)

    async def refresh(self, conversation: Conversation) -> None:
        await self._session.refresh(conversation)

    async def commit(self) -> None:
        await self._session.commit()

    async def rollback(self) -> None:
        await self._session.rollback()

    async def close(self, principal: Principal, conversation_id: uuid.UUID) -> Conversation:
        conversation = await self.get(principal, conversation_id)
        if conversation.status is ConversationStatus.CLOSED:
            return conversation
        if principal.is_customer and conversation.user_id != principal.user_id:
            raise NotFound
        if conversation.status is ConversationStatus.AGENT_ASSIGNED and principal.is_customer:
            raise Conflict(
                "A support specialist is handling this conversation; they will close it."
            )
        now = self._clock()
        conversation.status = ConversationStatus.CLOSED
        conversation.closed_at = now
        await self._session.commit()
        await self._audit.record(
            "conversation.close",
            outcome=AuditOutcome.SUCCESS,
            actor=principal,
            resource_type="conversation",
            resource_id=conversation.id,
        )
        return conversation
