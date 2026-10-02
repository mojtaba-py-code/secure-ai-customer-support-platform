"""Registry of tool definitions and their provider-facing schemas."""

from __future__ import annotations

from collections.abc import Iterable

from aegis.llm.schema import strict_json_schema
from aegis.llm.types import ToolSpec
from aegis.tools.base import SideEffect, ToolDefinition


class ToolRegistry:
    def __init__(self, definitions: Iterable[ToolDefinition]) -> None:
        self._tools: dict[str, ToolDefinition] = {}
        for definition in definitions:
            if definition.name in self._tools:
                msg = f"duplicate tool {definition.name}"
                raise ValueError(msg)
            self._tools[definition.name] = definition
        self._specs = {
            name: ToolSpec(
                name=name,
                description=d.description,
                input_schema=strict_json_schema(d.input_model),
            )
            for name, d in self._tools.items()
        }

    @property
    def names(self) -> frozenset[str]:
        return frozenset(self._tools)

    def get(self, name: str) -> ToolDefinition | None:
        return self._tools.get(name)

    def specs(self, names: Iterable[str]) -> tuple[ToolSpec, ...]:
        """Schemas for the given tools in a stable (registry) order - stable prefixes cache better."""
        wanted = set(names)
        return tuple(spec for name, spec in self._specs.items() if name in wanted)

    def with_side_effects(self, *effects: SideEffect) -> frozenset[str]:
        return frozenset(name for name, d in self._tools.items() if d.side_effect in effects)
