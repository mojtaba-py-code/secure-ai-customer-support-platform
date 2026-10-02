"""Tool definitions, per-turn context and results."""

from __future__ import annotations

import uuid
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any, Protocol

from pydantic import BaseModel, ConfigDict

from aegis.domain.enums import HandoffReason, Priority
from aegis.security.principal import Principal
from aegis.security.rbac import Permission
from aegis.services.actions import PendingActionService
from aegis.services.commerce import CustomerService, OrderService, ProductService
from aegis.services.tickets import TicketService


class SideEffect(StrEnum):
    READ = "read"
    WRITE = "write"  # low-risk, idempotent write (support ticket)
    PROPOSE = "propose"  # creates a pending action the customer must confirm
    ESCALATE = "escalate"


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True, frozen=True)


class ToolServices(Protocol):
    @property
    def orders(self) -> OrderService: ...

    @property
    def products(self) -> ProductService: ...

    @property
    def customers(self) -> CustomerService: ...

    @property
    def tickets(self) -> TicketService: ...

    @property
    def actions(self) -> PendingActionService: ...

    async def rollback(self) -> None: ...


@dataclass(slots=True)
class EscalationRequest:
    reason: HandoffReason
    summary: str


@dataclass(slots=True)
class ProposedAction:
    action_id: str
    action_type: str
    summary: str
    expires_at: str


@dataclass(slots=True)
class TurnToolState:
    escalation: EscalationRequest | None = None
    proposed_actions: list[ProposedAction] = field(default_factory=list)
    tickets_created: list[str] = field(default_factory=list)
    #: Serialized tool outputs - the evidence the output guard checks the reply against.
    evidence: list[str] = field(default_factory=list)
    calls_total: int = 0
    calls_by_tool: dict[str, int] = field(default_factory=dict)
    cache: dict[str, str] = field(default_factory=dict)
    tools_used: list[str] = field(default_factory=list)


@dataclass(slots=True)
class ToolContext:
    principal: Principal
    conversation_id: uuid.UUID
    message_id: uuid.UUID
    intent: str
    priority: Priority
    services: ToolServices
    state: TurnToolState


class ToolFailure(Exception):
    """An expected failure whose message is safe to show the model (and the customer)."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code
        self.message = message


Handler = Callable[[ToolContext, Any], Awaitable[BaseModel]]


@dataclass(frozen=True, slots=True)
class ToolDefinition:
    name: str
    description: str
    input_model: type[StrictModel]
    handler: Handler
    permission: Permission
    side_effect: SideEffect
    max_calls_per_turn: int = 3
