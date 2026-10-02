"""JSON Schemas for strict tool use and structured outputs.

Provider-side schema enforcement supports a subset of JSON Schema (no length/number/pattern
constraints, ``additionalProperties`` must be false, every property required). This module
derives that subset from a Pydantic model. The full model - with all its constraints - is still
used to validate what comes back: the provider guarantees *shape*, our code guarantees *content*.
"""

from __future__ import annotations

import copy
from typing import Any

from pydantic import BaseModel

_UNSUPPORTED = frozenset(
    {
        "title",
        "default",
        "examples",
        "minLength",
        "maxLength",
        "pattern",
        "minimum",
        "maximum",
        "exclusiveMinimum",
        "exclusiveMaximum",
        "multipleOf",
        "minItems",
        "maxItems",
        "uniqueItems",
        "minProperties",
        "maxProperties",
    }
)


def strict_json_schema(model: type[BaseModel]) -> dict[str, Any]:
    raw = model.model_json_schema()
    definitions = raw.pop("$defs", {})
    schema = _normalise(_inline(raw, definitions, depth=0))
    if not isinstance(schema, dict):
        msg = "a model schema must be a JSON object"
        raise TypeError(msg)
    return schema


def _inline(node: Any, definitions: dict[str, Any], *, depth: int) -> Any:
    if depth > 20:
        msg = "schema nesting too deep (recursive models are not supported)"
        raise ValueError(msg)
    if isinstance(node, dict):
        ref = node.get("$ref")
        if isinstance(ref, str) and ref.startswith("#/$defs/"):
            target = copy.deepcopy(definitions[ref.removeprefix("#/$defs/")])
            merged = {**target, **{k: v for k, v in node.items() if k != "$ref"}}
            return _inline(merged, definitions, depth=depth + 1)
        return {k: _inline(v, definitions, depth=depth + 1) for k, v in node.items()}
    if isinstance(node, list):
        return [_inline(item, definitions, depth=depth + 1) for item in node]
    return node


def _normalise(node: Any) -> Any:
    if isinstance(node, list):
        return [_normalise(item) for item in node]
    if not isinstance(node, dict):
        return node
    cleaned: dict[str, Any] = {}
    for key, value in node.items():
        if key in _UNSUPPORTED:
            continue
        if key == "properties" and isinstance(value, dict):
            # Keys of the properties mapping are field names (a field may be called "title").
            cleaned[key] = {name: _normalise(sub) for name, sub in value.items()}
        else:
            cleaned[key] = _normalise(value)
    if cleaned.get("type") == "object" or "properties" in cleaned:
        properties = cleaned.setdefault("properties", {})
        cleaned["type"] = "object"
        cleaned["required"] = list(properties)
        cleaned["additionalProperties"] = False
    return cleaned
