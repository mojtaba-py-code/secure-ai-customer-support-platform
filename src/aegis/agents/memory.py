"""Conversation memory.

* **Long-term** - all messages live in the database (encrypted). The model sees a bounded window:
  a rolling summary of older turns plus the last N messages, each redacted and truncated, under a
  total character budget (cost control and a smaller injection surface).
* **Short-term state** - small per-conversation flags (last intent, pending clarification) live
  in the shared key-value store with a TTL, serialised as JSON and validated on read (never
  pickle). Losing them is harmless: they default to "nothing pending".

History is replayed as *plain text only*: no provider reasoning blocks or tool traffic from earlier
turns is ever re-sent, so the history can be rebuilt freely without invalidating anything.
"""

from __future__ import annotations

import logging
import uuid

from pydantic import BaseModel, ConfigDict, Field, ValidationError

from aegis.agents.prompts import (
    SUMMARY_SYSTEM_PROMPT,
    render_customer_message,
    render_summary_request,
)
from aegis.core.errors import AegisError
from aegis.domain.enums import SenderType
from aegis.kv.base import KeyBuilder, KeyValueStore, KeyValueUnavailable
from aegis.llm.gateway import LLMGateway
from aegis.llm.types import ChatMessage, LLMRequest, LLMTask, StopReason
from aegis.models import Conversation, Message
from aegis.security.redaction import redact_for_llm
from aegis.security.text import truncate
from aegis.services.conversations import ConversationService

logger = logging.getLogger(__name__)

STATE_TTL_SECONDS = 86_400
MAX_HISTORY_MESSAGE_CHARS = 1_200
MAX_HISTORY_CHARS = 8_000
MAX_SUMMARY_CHARS = 1_500
KEEP_RECENT_AFTER_SUMMARY = 6


class ConversationState(BaseModel):
    model_config = ConfigDict(extra="ignore")

    last_intent: str | None = Field(default=None, max_length=40)
    clarification_pending: bool = False
    turns: int = Field(default=0, ge=0)


class ConversationStateStore:
    def __init__(self, store: KeyValueStore, keys: KeyBuilder) -> None:
        self._store = store
        self._keys = keys

    def _key(self, conversation_id: uuid.UUID) -> str:
        return self._keys.key("conv-state", str(conversation_id))

    async def get(self, conversation_id: uuid.UUID) -> ConversationState:
        try:
            raw = await self._store.get(self._key(conversation_id))
            return ConversationState.model_validate_json(raw) if raw else ConversationState()
        except (KeyValueUnavailable, ValidationError, ValueError):
            return ConversationState()

    async def save(self, conversation_id: uuid.UUID, state: ConversationState) -> None:
        try:
            await self._store.set(
                self._key(conversation_id), state.model_dump_json(), ttl_seconds=STATE_TTL_SECONDS
            )
        except KeyValueUnavailable:
            logger.warning(
                "conversation state not saved", extra={"event": "memory.state_save_failed"}
            )


def _as_chat(message: Message) -> ChatMessage | None:
    text = truncate(redact_for_llm(message.content).text, MAX_HISTORY_MESSAGE_CHARS)
    if message.sender_type is SenderType.CUSTOMER:
        return ChatMessage(role="user", text=render_customer_message(text))
    if message.sender_type is SenderType.ASSISTANT:
        return ChatMessage(role="assistant", text=text)
    if message.sender_type is SenderType.AGENT:
        return ChatMessage(role="assistant", text=f"(Reply from a human support specialist) {text}")
    return None


class ConversationMemory:
    def __init__(
        self,
        *,
        gateway: LLMGateway,
        history_messages: int,
        summary_trigger: int,
        summary_max_tokens: int,
    ) -> None:
        self._gateway = gateway
        self._history_messages = history_messages
        self._summary_trigger = summary_trigger
        self._summary_max_tokens = summary_max_tokens

    async def history(
        self,
        conversations: ConversationService,
        conversation: Conversation,
        *,
        before_sequence: int,
    ) -> tuple[str | None, list[ChatMessage]]:
        """(summary, recent messages) preceding ``before_sequence``, oldest first."""
        if self._history_messages == 0:
            return conversation.summary, []
        recent = await conversations.recent_messages(
            conversation.id, limit=self._history_messages + 1
        )
        recent = [m for m in recent if m.sequence < before_sequence][-self._history_messages :]
        chats = [c for m in recent if (c := _as_chat(m)) is not None]
        budget = MAX_HISTORY_CHARS
        kept: list[ChatMessage] = []
        for chat in reversed(chats):
            budget -= len(chat.text)
            if budget < 0:
                break
            kept.append(chat)
        kept.reverse()
        while kept and kept[0].role != "user":
            kept.pop(0)  # a request must start with a user turn
        return conversation.summary, kept

    async def maybe_summarize(
        self, conversations: ConversationService, conversation: Conversation
    ) -> bool:
        """Fold older messages into the rolling summary once enough have accumulated."""
        through = conversation.message_count - KEEP_RECENT_AFTER_SUMMARY
        if through - conversation.summarized_through < self._summary_trigger:
            return False
        messages = await conversations.messages_in_range(
            conversation.id, after=conversation.summarized_through, through=through
        )
        transcript = [
            (m.sender_type.value, truncate(redact_for_llm(m.content).text, 600))
            for m in messages
            if m.sender_type is not SenderType.SYSTEM
        ]
        if not transcript:
            return False
        request = LLMRequest(
            task=LLMTask.SUMMARIZE,
            system=SUMMARY_SYSTEM_PROMPT,
            messages=[
                ChatMessage(
                    role="user", text=render_summary_request(conversation.summary, transcript)
                )
            ],
            max_output_tokens=self._summary_max_tokens,
            metadata={"transcript": transcript},
        )
        try:
            response = await self._gateway.complete(
                request, user_id=conversation.user_id, conversation_id=conversation.id
            )
        except AegisError:
            logger.warning("summary skipped", extra={"event": "memory.summary_failed"})
            return False
        if response.stop_reason is not StopReason.END_TURN or not response.text.strip():
            return False
        conversation.summary = truncate(redact_for_llm(response.text).text, MAX_SUMMARY_CHARS)
        conversation.summarized_through = through
        await conversations.commit()
        return True
