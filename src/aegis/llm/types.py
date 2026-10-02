"""Provider-neutral request/response types."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any, Literal


class LLMTask(StrEnum):
    CLASSIFY = "classify"
    AGENT = "agent"
    SUMMARIZE = "summarize"


class StopReason(StrEnum):
    END_TURN = "end_turn"
    TOOL_USE = "tool_use"
    MAX_TOKENS = "max_tokens"
    REFUSAL = "refusal"
    OTHER = "other"


@dataclass(frozen=True, slots=True)
class ToolSpec:
    name: str
    description: str
    input_schema: dict[str, Any]


@dataclass(frozen=True, slots=True)
class ToolCall:
    id: str
    name: str
    arguments: dict[str, Any]


@dataclass(frozen=True, slots=True)
class ToolResult:
    tool_call_id: str
    content: str
    is_error: bool = False


@dataclass(frozen=True, slots=True)
class ContextDocument:
    """A retrieved knowledge chunk offered to the model as *data* (citation index is 1-based)."""

    index: int
    source_id: str
    document_id: str
    title: str
    section: str
    text: str
    score: float = 0.0
    category: str = ""


@dataclass(frozen=True, slots=True)
class ChatMessage:
    role: Literal["user", "assistant"]
    text: str = ""
    tool_calls: tuple[ToolCall, ...] = ()
    tool_results: tuple[ToolResult, ...] = ()
    documents: tuple[ContextDocument, ...] = ()
    #: Provider-native assistant content, replayed verbatim inside one agent turn (keeps
    #: reasoning blocks intact). Never persisted and never shared across turns.
    provider_raw: Any = None


@dataclass(frozen=True, slots=True)
class TokenUsage:
    input_tokens: int = 0
    output_tokens: int = 0
    cache_read_tokens: int = 0
    cache_write_tokens: int = 0

    @property
    def total(self) -> int:
        return (
            self.input_tokens
            + self.output_tokens
            + self.cache_read_tokens
            + self.cache_write_tokens
        )


@dataclass(slots=True)
class LLMRequest:
    task: LLMTask
    system: str
    messages: list[ChatMessage]
    tools: tuple[ToolSpec, ...] = ()
    response_schema: dict[str, Any] | None = None
    max_output_tokens: int = 1_024
    #: Application metadata for routing, accounting and deterministic providers. Remote
    #: providers receive only an opaque ``user_ref``.
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class LLMResponse:
    text: str
    tool_calls: tuple[ToolCall, ...]
    stop_reason: StopReason
    usage: TokenUsage
    model: str
    provider: str
    latency_ms: int = 0
    raw_content: Any = None
    refusal_category: str | None = None
    degraded: bool = False
    degraded_reason: str | None = None
    cost_usd: float = 0.0
