"""Loading and validating the declarative intent registry (``intents.toml``)."""

from __future__ import annotations

import tomllib
from collections.abc import Iterable
from importlib import resources
from typing import Annotated, Any

from pydantic import BaseModel, ConfigDict, Field, StringConstraints

from aegis.domain.enums import HandoffReason, KnowledgeCategory, Priority

ALWAYS_AVAILABLE_TOOLS = ("request_human_agent",)
FALLBACK_INTENT = "general_question"


class IntentDefinition(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    name: Annotated[str, StringConstraints(pattern=r"^[a-z][a-z_]{2,39}$")]
    description: Annotated[str, StringConstraints(min_length=10, max_length=300)]
    default_priority: Priority
    tools: tuple[str, ...] = ()
    knowledge: tuple[KnowledgeCategory, ...] = ()
    keywords: tuple[Annotated[str, StringConstraints(min_length=2, max_length=60)], ...] = ()
    always_escalate: bool = False
    escalation_reason: HandoffReason | None = None


class _RegistryFile(BaseModel):
    model_config = ConfigDict(extra="forbid")

    intent: list[IntentDefinition] = Field(min_length=1)


class IntentRegistry:
    def __init__(self, intents: Iterable[IntentDefinition], *, known_tools: frozenset[str]) -> None:
        self._intents: dict[str, IntentDefinition] = {}
        for intent in intents:
            if intent.name in self._intents:
                msg = f"duplicate intent {intent.name}"
                raise ValueError(msg)
            unknown = set(intent.tools) - known_tools
            if unknown:
                msg = f"intent {intent.name} references unknown tools: {sorted(unknown)}"
                raise ValueError(msg)
            tools = tuple(dict.fromkeys((*intent.tools, *ALWAYS_AVAILABLE_TOOLS)))
            self._intents[intent.name] = intent.model_copy(update={"tools": tools})
        if FALLBACK_INTENT not in self._intents:
            msg = f"the registry must define the fallback intent {FALLBACK_INTENT!r}"
            raise ValueError(msg)

    @classmethod
    def load_default(cls, *, known_tools: frozenset[str]) -> IntentRegistry:
        raw = resources.files("aegis.agents").joinpath("intents.toml").read_text(encoding="utf-8")
        return cls.from_toml(raw, known_tools=known_tools)

    @classmethod
    def from_toml(cls, raw: str, *, known_tools: frozenset[str]) -> IntentRegistry:
        data: dict[str, Any] = tomllib.loads(raw)
        parsed = _RegistryFile.model_validate(data)
        return cls(parsed.intent, known_tools=known_tools)

    @property
    def names(self) -> tuple[str, ...]:
        return tuple(self._intents)

    def get(self, name: str) -> IntentDefinition | None:
        return self._intents.get(name)

    def resolve(self, name: str | None) -> IntentDefinition:
        return self._intents.get(name or "", self._intents[FALLBACK_INTENT])

    def all(self) -> tuple[IntentDefinition, ...]:
        return tuple(self._intents.values())
