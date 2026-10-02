"""Test doubles: a scripted language model and a capturing e-mail sender."""

from __future__ import annotations

import itertools
import json
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

from aegis.llm.types import LLMRequest, LLMResponse, LLMTask, StopReason, TokenUsage, ToolCall
from aegis.services.email import OutgoingEmail

_ids = itertools.count(1)

Step = LLMResponse | Exception | Callable[[LLMRequest], LLMResponse]


def reply(
    text: str, *, stop: StopReason = StopReason.END_TURN, model: str = "claude-opus-5-5"
) -> LLMResponse:
    return LLMResponse(
        text=text,
        tool_calls=(),
        stop_reason=stop,
        usage=TokenUsage(input_tokens=100, output_tokens=20),
        model=model,
        provider="scripted",
    )


def tool_call(name: str, arguments: dict[str, Any], *, text: str = "") -> LLMResponse:
    return LLMResponse(
        text=text,
        tool_calls=(ToolCall(id=f"toolu_{next(_ids)}", name=name, arguments=arguments),),
        stop_reason=StopReason.TOOL_USE,
        usage=TokenUsage(input_tokens=100, output_tokens=20),
        model="claude-opus-5-5",
        provider="scripted",
    )


def classification(
    intent: str,
    *,
    confidence: float = 0.9,
    priority: str = "medium",
    requires_human: bool = False,
    order_numbers: list[str] | None = None,
    sentiment: str = "neutral",
) -> LLMResponse:
    return reply(
        json.dumps(
            {
                "intent": intent,
                "priority": priority,
                "sentiment": sentiment,
                "confidence": confidence,
                "requires_tool": True,
                "requires_human": requires_human,
                "order_numbers": order_numbers or [],
                "language": "en",
                "summary": f"Customer asks about {intent}.",
            }
        ),
        model="claude-haiku-4-5",
    )


@dataclass
class ScriptedLLM:
    """Plays back scripted responses per task and records every request it receives."""

    agent: list[Step] = field(default_factory=list)
    classify: list[Step] = field(default_factory=list)
    summarize: list[Step] = field(default_factory=list)
    requests: list[LLMRequest] = field(default_factory=list)
    default_agent: Step | None = None

    @property
    def name(self) -> str:
        return "scripted"

    async def close(self) -> None:
        return None

    async def complete(self, request: LLMRequest, *, model: str) -> LLMResponse:
        self.requests.append(request)
        queue = {
            LLMTask.AGENT: self.agent,
            LLMTask.CLASSIFY: self.classify,
            LLMTask.SUMMARIZE: self.summarize,
        }[request.task]
        if queue:
            step = queue.pop(0)
        elif request.task is LLMTask.AGENT and self.default_agent is not None:
            step = self.default_agent
        elif request.task is LLMTask.SUMMARIZE:
            step = reply("Summary of the conversation.", model="claude-haiku-4-5")
        else:
            msg = f"no scripted response left for {request.task}"
            raise AssertionError(msg)
        if isinstance(step, Exception):
            raise step
        if callable(step) and not isinstance(step, LLMResponse):
            return step(request)
        return step

    def agent_requests(self) -> list[LLMRequest]:
        return [r for r in self.requests if r.task is LLMTask.AGENT]


@dataclass
class CapturingEmailSender:
    sent: list[OutgoingEmail] = field(default_factory=list)

    async def send(self, message: OutgoingEmail) -> None:
        self.sent.append(message)
