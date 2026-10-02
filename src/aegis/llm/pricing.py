"""Approximate model pricing (USD per million tokens) for cost tracking and budgets.

Figures are Anthropic first-party list prices (cached 2026-09). Unknown models are priced at
the most expensive tier so budgets fail safe rather than under-count.
"""

from __future__ import annotations

from dataclasses import dataclass

from aegis.llm.types import TokenUsage


@dataclass(frozen=True, slots=True)
class ModelPrice:
    input: float
    output: float
    cache_read: float
    cache_write: float


PRICES: dict[str, ModelPrice] = {
    "claude-fable-5-1": ModelPrice(10.0, 50.0, 0.25, 12.5),
    "claude-opus-5-5": ModelPrice(4.0, 20.0, 0.20, 5.0),
    "claude-opus-5": ModelPrice(5.0, 25.0, 0.50, 6.25),
    "claude-sonnet-5-5": ModelPrice(2.0, 10.0, 0.20, 2.5),
    "claude-sonnet-5": ModelPrice(2.0, 10.0, 0.20, 2.5),
    "claude-haiku-4-5": ModelPrice(1.0, 5.0, 0.10, 1.25),
    "offline": ModelPrice(0.0, 0.0, 0.0, 0.0),
}
_FALLBACK_PRICE = ModelPrice(10.0, 50.0, 1.0, 12.5)


def price_for(model: str) -> ModelPrice:
    return PRICES.get(model, _FALLBACK_PRICE)


def estimate_cost(model: str, usage: TokenUsage) -> float:
    price = price_for(model)
    total = (
        usage.input_tokens * price.input
        + usage.output_tokens * price.output
        + usage.cache_read_tokens * price.cache_read
        + usage.cache_write_tokens * price.cache_write
    )
    return round(total / 1_000_000, 6)
