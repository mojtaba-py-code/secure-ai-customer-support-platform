"""Prometheus metrics (a dedicated registry, exposed at ``/metrics`` behind a bearer token).

Label values are always drawn from small closed sets (route templates, tool names, intents,
outcomes) so an attacker cannot explode metric cardinality with crafted input.
"""

from __future__ import annotations

from prometheus_client import CollectorRegistry, Counter, Gauge, Histogram, generate_latest

REGISTRY = CollectorRegistry(auto_describe=True)

HTTP_REQUESTS = Counter(
    "aegis_http_requests_total", "HTTP requests", ["method", "route", "status"], registry=REGISTRY
)
HTTP_LATENCY = Histogram(
    "aegis_http_request_duration_seconds",
    "HTTP request latency",
    ["method", "route"],
    buckets=(0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10, 30, 60),
    registry=REGISTRY,
)
LLM_REQUESTS = Counter(
    "aegis_llm_requests_total",
    "Model API calls",
    ["provider", "task", "outcome"],
    registry=REGISTRY,
)
LLM_TOKENS = Counter(
    "aegis_llm_tokens_total", "Model tokens", ["provider", "model", "kind"], registry=REGISTRY
)
LLM_COST = Counter(
    "aegis_llm_cost_usd_total", "Estimated model spend (USD)", ["model"], registry=REGISTRY
)
LLM_LATENCY = Histogram(
    "aegis_llm_latency_seconds",
    "Model call latency",
    ["provider", "task"],
    buckets=(0.25, 0.5, 1, 2, 4, 8, 16, 32, 64),
    registry=REGISTRY,
)
AGENT_TURNS = Counter(
    "aegis_agent_turns_total", "Agent turns", ["intent", "outcome"], registry=REGISTRY
)
TOOL_CALLS = Counter(
    "aegis_tool_calls_total", "Tool invocations", ["tool", "outcome"], registry=REGISTRY
)
ESCALATIONS = Counter("aegis_escalations_total", "Human handoffs", ["reason"], registry=REGISTRY)
SECURITY_EVENTS = Counter(
    "aegis_security_events_total", "Security-relevant events", ["event"], registry=REGISTRY
)
RATE_LIMITED = Counter(
    "aegis_rate_limited_total", "Rejected by rate limiting", ["policy"], registry=REGISTRY
)
RAG_RETRIEVALS = Counter(
    "aegis_rag_retrievals_total", "Knowledge retrievals", ["outcome"], registry=REGISTRY
)
RAG_CHUNKS = Histogram(
    "aegis_rag_chunks_returned",
    "Chunks returned per retrieval",
    buckets=(0, 1, 2, 3, 5, 8),
    registry=REGISTRY,
)
CIRCUIT_STATE = Gauge(
    "aegis_circuit_open",
    "1 when a circuit breaker is open or half-open",
    ["circuit"],
    registry=REGISTRY,
)
GUARD_VIOLATIONS = Counter(
    "aegis_output_guard_violations_total", "Output guard findings", ["kind"], registry=REGISTRY
)


def render_metrics() -> bytes:
    return generate_latest(REGISTRY)


def security_event(event: str) -> None:
    SECURITY_EVENTS.labels(event=event).inc()
