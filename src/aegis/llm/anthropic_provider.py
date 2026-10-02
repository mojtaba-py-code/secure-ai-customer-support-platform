"""Claude via the official Anthropic SDK.

Request shape (per current API guidance):

* Agent turns run on the configured Opus-class model with adaptive thinking (the default, so the
  ``thinking`` field is omitted) and an explicit ``output_config.effort``. Tools are declared with
  ``strict: true`` and ``tool_choice`` stays ``auto`` (forced tool choice is rejected by current
  models); the tool executor re-validates every argument anyway.
* Classification and summaries run on a small model with structured output
  (``output_config.format`` + JSON schema); the reply is still validated with Pydantic.
* Refusals: ``stop_reason == "refusal"`` is checked before any content is read; on models that
  support it, server-side fallback (``fallbacks="default"``) is enabled so a false-positive
  safety decline does not become an outage.
* Within one agent turn the assistant content is replayed verbatim (thinking blocks included);
  across turns only plain text is sent, so no reasoning block is ever replayed into an edited
  history.
* Prompt caching uses top-level automatic caching; the system prompt is static per deployment.
* Only an opaque ``metadata.user_id`` (a fingerprint) is sent - never names or e-mail addresses.
"""

from __future__ import annotations

import logging
import time
from typing import Any

import anthropic
import httpx2

from aegis.llm.base import LLMRequestRejected, LLMUnavailable
from aegis.llm.types import (
    ChatMessage,
    LLMRequest,
    LLMResponse,
    LLMTask,
    StopReason,
    TokenUsage,
    ToolCall,
)

logger = logging.getLogger(__name__)

FALLBACK_BETA = "server-side-fallback-2026-07-01"
#: Models that accept ``fallbacks="default"`` (server-side refusal fallback).
FALLBACK_CAPABLE_MODELS = frozenset(
    {"claude-opus-5-5", "claude-opus-5", "claude-sonnet-5-5", "claude-fable-5-1"}
)
#: Models that accept ``output_config.effort``.
EFFORT_CAPABLE_MODELS = frozenset(
    {
        "claude-fable-5-1",
        "claude-fable-5",
        "claude-opus-5-5",
        "claude-opus-5",
        "claude-opus-4-8",
        "claude-opus-4-7",
        "claude-opus-4-6",
        "claude-sonnet-5-5",
        "claude-sonnet-5",
        "claude-sonnet-4-6",
    }
)
_REPLAY_DROP_BEFORE_FALLBACK = frozenset({"thinking", "redacted_thinking", "tool_use"})
_STOP_REASONS = {
    "end_turn": StopReason.END_TURN,
    "stop_sequence": StopReason.END_TURN,
    "tool_use": StopReason.TOOL_USE,
    "max_tokens": StopReason.MAX_TOKENS,
    "model_context_window_exceeded": StopReason.MAX_TOKENS,
    "refusal": StopReason.REFUSAL,
}


class AnthropicProvider:
    def __init__(
        self,
        *,
        api_key: str,
        timeout_seconds: float,
        max_retries: int,
        agent_effort: str,
        refusal_fallback: bool,
        prompt_caching: bool,
        base_url: str | None = None,
        http_client: httpx2.AsyncClient | None = None,
    ) -> None:
        self._client = anthropic.AsyncAnthropic(
            api_key=api_key,
            base_url=base_url,
            timeout=anthropic.Timeout(timeout_seconds, connect=min(5.0, timeout_seconds)),
            max_retries=max_retries,
            http_client=http_client,
        )
        self._effort = agent_effort
        self._refusal_fallback = refusal_fallback
        self._prompt_caching = prompt_caching

    @property
    def name(self) -> str:
        return "anthropic"

    async def close(self) -> None:
        await self._client.close()

    # ------------------------------------------------------------------------------------------
    def build_params(self, request: LLMRequest, *, model: str) -> dict[str, Any]:
        params: dict[str, Any] = {
            "model": model,
            "max_tokens": request.max_output_tokens,
            "system": request.system,
            "messages": [self._message_param(m) for m in request.messages],
        }
        output_config: dict[str, Any] = {}
        if request.task is LLMTask.AGENT and model in EFFORT_CAPABLE_MODELS:
            output_config["effort"] = self._effort
        if request.response_schema is not None:
            output_config["format"] = {"type": "json_schema", "schema": request.response_schema}
        if output_config:
            params["output_config"] = output_config
        if request.tools:
            params["tools"] = [
                {
                    "name": tool.name,
                    "description": tool.description,
                    "input_schema": tool.input_schema,
                    "strict": True,
                }
                for tool in request.tools
            ]
        if self._prompt_caching:
            params["cache_control"] = {"type": "ephemeral"}
        user_ref = request.metadata.get("user_ref")
        if isinstance(user_ref, str) and user_ref:
            params["metadata"] = {"user_id": user_ref}
        return params

    @staticmethod
    def _message_param(message: ChatMessage) -> dict[str, Any]:
        if message.role == "assistant":
            if message.provider_raw is not None:
                return {"role": "assistant", "content": _replayable(message.provider_raw)}
            content: list[dict[str, Any]] = []
            if message.text:
                content.append({"type": "text", "text": message.text})
            content.extend(
                {"type": "tool_use", "id": call.id, "name": call.name, "input": call.arguments}
                for call in message.tool_calls
            )
            return {
                "role": "assistant",
                "content": content or [{"type": "text", "text": "(no content)"}],
            }
        if message.tool_results:
            return {
                "role": "user",
                "content": [
                    {
                        "type": "tool_result",
                        "tool_use_id": result.tool_call_id,
                        "content": result.content,
                        "is_error": result.is_error,
                    }
                    for result in message.tool_results
                ],
            }
        return {"role": "user", "content": message.text}

    # ------------------------------------------------------------------------------------------
    async def complete(self, request: LLMRequest, *, model: str) -> LLMResponse:
        params = self.build_params(request, model=model)
        started = time.perf_counter()
        try:
            if self._refusal_fallback and model in FALLBACK_CAPABLE_MODELS:
                message = await self._client.beta.messages.create(
                    **params, betas=[FALLBACK_BETA], fallbacks="default"
                )
            else:
                message = await self._client.messages.create(**params)
        except (anthropic.APIConnectionError, anthropic.RateLimitError) as exc:
            raise LLMUnavailable(
                log_message=f"anthropic transient failure: {type(exc).__name__}"
            ) from exc
        except (anthropic.AuthenticationError, anthropic.PermissionDeniedError) as exc:
            logger.critical("anthropic credentials rejected", extra={"event": "llm.auth_failed"})
            raise LLMUnavailable(
                log_message=f"anthropic credentials rejected: {type(exc).__name__}"
            ) from exc
        except anthropic.APIStatusError as exc:
            if exc.status_code >= 500 or exc.status_code in (408, 409, 429, 529):
                raise LLMUnavailable(log_message=f"anthropic HTTP {exc.status_code}") from exc
            raise LLMRequestRejected(
                log_message=f"anthropic rejected request: HTTP {exc.status_code}"
            ) from exc
        except anthropic.AnthropicError as exc:
            raise LLMUnavailable(
                log_message=f"anthropic client error: {type(exc).__name__}"
            ) from exc
        latency_ms = int((time.perf_counter() - started) * 1000)
        return self._parse(message, latency_ms=latency_ms)

    def _parse(self, message: Any, *, latency_ms: int) -> LLMResponse:
        stop = _STOP_REASONS.get(str(message.stop_reason), StopReason.OTHER)
        usage = message.usage
        token_usage = TokenUsage(
            input_tokens=int(getattr(usage, "input_tokens", 0) or 0),
            output_tokens=int(getattr(usage, "output_tokens", 0) or 0),
            cache_read_tokens=int(getattr(usage, "cache_read_input_tokens", 0) or 0),
            cache_write_tokens=int(getattr(usage, "cache_creation_input_tokens", 0) or 0),
        )
        if stop is StopReason.REFUSAL:
            details = getattr(message, "stop_details", None)
            category = getattr(details, "category", None) if details is not None else None
            return LLMResponse(
                text="",
                tool_calls=(),
                stop_reason=stop,
                usage=token_usage,
                model=str(message.model),
                provider=self.name,
                latency_ms=latency_ms,
                refusal_category=str(category) if category else None,
            )
        texts: list[str] = []
        calls: list[ToolCall] = []
        for block in message.content:
            block_type = getattr(block, "type", None)
            if block_type == "text":
                texts.append(str(block.text))
            elif block_type == "tool_use":
                arguments = block.input if isinstance(block.input, dict) else {}
                calls.append(
                    ToolCall(id=str(block.id), name=str(block.name), arguments=dict(arguments))
                )
        return LLMResponse(
            text="".join(texts).strip(),
            tool_calls=tuple(calls),
            stop_reason=stop,
            usage=token_usage,
            model=str(message.model),
            provider=self.name,
            latency_ms=latency_ms,
            raw_content=list(message.content),
        )


def _replayable(blocks: Any) -> list[Any]:
    """Assistant content to echo back inside the same turn.

    After a server-side fallback, reasoning and tool-use blocks produced *before* the last
    ``fallback`` marker belong to the model that declined and must not be echoed.
    """
    items = list(blocks)
    last_fallback = max(
        (i for i, b in enumerate(items) if getattr(b, "type", None) == "fallback"), default=-1
    )
    if last_fallback < 0:
        return items
    return [
        b
        for i, b in enumerate(items)
        if i > last_fallback or getattr(b, "type", None) not in _REPLAY_DROP_BEFORE_FALLBACK
    ]
