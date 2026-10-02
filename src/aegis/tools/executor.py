"""Tool execution: the enforcement point between a model's *request* and the business.

For every tool call proposed by the model:

1. the tool must exist **and** be in this turn's allow-list (least privilege per intent and
   risk level) - otherwise the call is refused and recorded as a security event;
2. per-turn call budgets are enforced (total and per tool); identical repeated calls are
   answered from the turn cache instead of re-executing;
3. the arguments are validated against the tool's Pydantic model (types, patterns, lengths,
   no extra fields) - the provider-side schema is a convenience, not a guarantee;
4. the principal's role must hold the tool's permission (RBAC);
5. the handler runs with a timeout; ownership is enforced by the services underneath;
6. failures become structured, customer-safe error results (never stack traces or SQL);
7. outputs are size-capped JSON, kept as *evidence* for the output guard, logged by name and
   outcome only, and side-effecting calls are audited.
"""

from __future__ import annotations

import asyncio
import json
import logging
import time
from dataclasses import dataclass

from pydantic import BaseModel, ValidationError

from aegis.core.errors import (
    AegisError,
    Conflict,
    DependencyUnavailable,
    NotFound,
    PermissionDenied,
    RateLimited,
    ValidationFailed,
)
from aegis.domain.enums import AuditOutcome
from aegis.llm.types import ToolCall, ToolResult
from aegis.observability import metrics
from aegis.security.crypto import fingerprint
from aegis.services.audit import AuditService
from aegis.tools.base import SideEffect, ToolContext, ToolDefinition, ToolFailure, TurnToolState
from aegis.tools.registry import ToolRegistry

logger = logging.getLogger(__name__)

MAX_OUTPUT_CHARS = 6_000
NOT_PERMITTED = "This action is not permitted for your account."


@dataclass(frozen=True, slots=True)
class _Failure:
    code: str
    outcome: str
    message: str | None  # None = use the exception's public message
    rollback: bool = False


# Expected exception -> model-visible error. Order matters (subclasses first).
_FAILURES: tuple[tuple[tuple[type[BaseException], ...], _Failure], ...] = (
    ((NotFound,), _Failure("not_found", "not_found", None)),
    ((ValidationFailed, Conflict), _Failure("not_allowed", "rejected", None)),
    ((PermissionDenied,), _Failure("not_permitted", "denied", NOT_PERMITTED)),
    ((RateLimited,), _Failure("limit_reached", "limited", None)),
    (
        (DependencyUnavailable, TimeoutError),
        _Failure(
            "temporarily_unavailable",
            "unavailable",
            "This information is temporarily unavailable.",
            rollback=True,
        ),
    ),
    ((AegisError,), _Failure("failed", "failed", None, rollback=True)),
)


def _error(call: ToolCall, code: str, message: str) -> ToolResult:
    return ToolResult(
        tool_call_id=call.id,
        content=json.dumps({"error": code, "message": message}, ensure_ascii=False),
        is_error=True,
    )


def _cache_key(call: ToolCall) -> str:
    return f"{call.name}:{json.dumps(call.arguments, sort_keys=True, default=str)}"


class ToolExecutor:
    def __init__(
        self,
        registry: ToolRegistry,
        *,
        audit: AuditService,
        timeout_seconds: float,
        max_calls_per_turn: int,
    ) -> None:
        self._registry = registry
        self._audit = audit
        self._timeout = timeout_seconds
        self._max_calls = max_calls_per_turn

    async def execute(
        self, call: ToolCall, ctx: ToolContext, *, allowed: frozenset[str]
    ) -> ToolResult:
        started = time.perf_counter()
        result, outcome = await self._execute(call, ctx, allowed)
        elapsed_ms = int((time.perf_counter() - started) * 1000)
        tool_label = call.name if call.name in self._registry.names else "unknown"
        metrics.TOOL_CALLS.labels(tool=tool_label, outcome=outcome).inc()
        logger.info(
            "tool call",
            extra={
                "event": "tool.call",
                "tool": call.name[:64],
                "outcome": outcome,
                "duration_ms": elapsed_ms,
                "args_fingerprint": fingerprint(
                    json.dumps(call.arguments, sort_keys=True, default=str)
                ),
            },
        )
        return result

    async def _execute(
        self, call: ToolCall, ctx: ToolContext, allowed: frozenset[str]
    ) -> tuple[ToolResult, str]:
        definition = self._registry.get(call.name)
        if definition is None or call.name not in allowed:
            await self._audit_denial(
                ctx, call.name, known=definition is not None, reason="not_allowed"
            )
            metrics.security_event("tool_not_allowed")
            message = "That tool is not available for this request."
            return _error(call, "tool_not_available", message), "denied"

        cached = ctx.state.cache.get(_cache_key(call))
        if cached is not None:
            return ToolResult(tool_call_id=call.id, content=cached), "cached"
        limited = self._consume_budget(call, ctx.state, definition)
        if limited is not None:
            return limited, "limited"

        try:
            arguments = definition.input_model.model_validate(call.arguments)
        except ValidationError as exc:
            fields = sorted(
                {".".join(str(p) for p in err["loc"]) or "input" for err in exc.errors()}
            )
            metrics.security_event("tool_invalid_arguments")
            message = f"Invalid or missing arguments: {', '.join(fields)[:200]}."
            return _error(call, "invalid_arguments", message), "invalid"

        if not ctx.principal.has(definition.permission):
            await self._audit_denial(ctx, call.name, known=True, reason="permission")
            metrics.security_event("tool_permission_denied")
            return _error(call, "not_permitted", NOT_PERMITTED), "denied"

        try:
            async with asyncio.timeout(self._timeout):
                output = await definition.handler(ctx, arguments)
        except ToolFailure as exc:
            return _error(call, exc.code, exc.message), "failed"
        except Exception as exc:  # noqa: BLE001 - mapped to a safe result; unknown errors are logged
            return await self._failure(call, ctx, exc)
        return await self._success(call, ctx, definition, output)

    def _consume_budget(
        self, call: ToolCall, state: TurnToolState, definition: ToolDefinition
    ) -> ToolResult | None:
        if state.calls_total >= self._max_calls:
            message = "The tool call limit for this message was reached."
            return _error(call, "tool_limit_reached", message)
        if state.calls_by_tool.get(call.name, 0) >= definition.max_calls_per_turn:
            return _error(
                call, "tool_limit_reached", f"{call.name} was already used for this message."
            )
        state.calls_total += 1
        state.calls_by_tool[call.name] = state.calls_by_tool.get(call.name, 0) + 1
        return None

    async def _failure(
        self, call: ToolCall, ctx: ToolContext, exc: Exception
    ) -> tuple[ToolResult, str]:
        for types, failure in _FAILURES:
            if isinstance(exc, types):
                if failure.rollback:
                    await ctx.services.rollback()
                if failure.code == "not_permitted":
                    metrics.security_event("tool_permission_denied")
                message = failure.message or str(
                    getattr(exc, "public_message", "The request failed.")
                )
                return _error(call, failure.code, message), failure.outcome
        await ctx.services.rollback()
        logger.error("tool crashed", exc_info=exc, extra={"event": "tool.crash", "tool": call.name})
        message = "Something went wrong while looking this up."
        return _error(call, "internal_error", message), "error"

    async def _success(
        self, call: ToolCall, ctx: ToolContext, definition: ToolDefinition, output: BaseModel
    ) -> tuple[ToolResult, str]:
        content = output.model_dump_json()
        if len(content) > MAX_OUTPUT_CHARS:
            too_large = json.dumps(
                {"error": "output_too_large", "message": "The result was too large."}
            )
            return ToolResult(tool_call_id=call.id, content=too_large, is_error=True), "too_large"
        state = ctx.state
        state.cache[_cache_key(call)] = content
        state.evidence.append(content)
        state.tools_used.append(call.name)
        if definition.side_effect is not SideEffect.READ:
            await self._audit.record(
                f"agent.tool.{call.name}",
                outcome=AuditOutcome.SUCCESS,
                actor=ctx.principal,
                resource_type="conversation",
                resource_id=ctx.conversation_id,
                details={"side_effect": definition.side_effect.value},
            )
        return ToolResult(tool_call_id=call.id, content=content), "ok"

    async def _audit_denial(self, ctx: ToolContext, tool: str, *, known: bool, reason: str) -> None:
        await self._audit.record(
            "agent.tool_denied",
            outcome=AuditOutcome.DENIED,
            actor=ctx.principal,
            resource_type="conversation",
            resource_id=ctx.conversation_id,
            details={"tool": tool[:64], "known": known, "reason": reason},
        )
