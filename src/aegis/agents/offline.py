"""A deterministic, offline stand-in for the language model.

It implements the same provider interface as the Claude adapter, so the *entire* pipeline -
classification, policy, retrieval, the tool loop through the real executor and database, the
output guard, persistence - runs without an API key. It is used for local development, CI, demos,
and as the degraded-mode fallback when the model API is down or a budget is exhausted.

It is not a language model: it classifies with the keyword rules, plans tool calls from the
intent and the reference numbers in the message, and composes replies from templates filled
exclusively with tool results and retrieved documents - so its answers are grounded by
construction, if less fluent. Replies are in English.
"""

from __future__ import annotations

import json
import re
import uuid
from typing import Any

from aegis.agents.intents import IntentRegistry
from aegis.agents.prompts import unwrap_customer_message
from aegis.agents.rules import RuleBasedClassifier
from aegis.agents.signals import detect_signals
from aegis.llm.types import (
    ContextDocument,
    LLMRequest,
    LLMResponse,
    LLMTask,
    StopReason,
    TokenUsage,
    ToolCall,
)

_EXPLICIT_REFUND = re.compile(r"\b(?:refund|money back|reimburse|return (?:it|this|them|the))\b")
_POLICY_QUESTION = re.compile(
    r"\b(?:policy|policies|how long|how many days|how do(?:es)?|what (?:is|are)|can i|do you|is it possible)\b"
)
_REFUND_STATUS = re.compile(r"\b(?:status|where is|when will|received|already)\b")
_EXPLICIT_CANCEL = re.compile(r"\bcancel(?:l?ing|l?ed)?\b")
_SENTENCE = re.compile(r"(?<=[.!?])\s+")
_REASONS = (
    ("damaged", ("damaged", "dented", "cracked", "smashed")),
    (
        "defective",
        ("defective", "broken", "not working", "doesn't work", "faulty", "stopped working"),
    ),
    (
        "wrong_item",
        ("wrong item", "wrong product", "wrong colour", "wrong color", "not what i ordered"),
    ),
    ("not_as_described", ("not as described", "different from", "misleading")),
    ("late_delivery", ("late", "too long", "never arrived")),
    ("no_longer_needed", ("no longer need", "don't need", "changed my mind", "not needed")),
)


def _guess_reason(text: str) -> str:
    lowered = text.lower()
    for reason, words in _REASONS:
        if any(word in lowered for word in words):
            return reason
    return "other"


def _first_sentences(text: str, count: int = 2, limit: int = 350) -> str:
    flat = " ".join(line.strip("-*# ").strip() for line in text.splitlines() if line.strip())
    sentences = _SENTENCE.split(flat)
    excerpt = " ".join(sentences[:count]).strip()
    return excerpt if len(excerpt) <= limit else excerpt[: limit - 3].rstrip() + "..."


class OfflineSupportModel:
    def __init__(self, registry: IntentRegistry, rules: RuleBasedClassifier) -> None:
        self._registry = registry
        self._rules = rules

    @property
    def name(self) -> str:
        return "offline"

    async def close(self) -> None:
        return None

    async def complete(self, request: LLMRequest, *, model: str) -> LLMResponse:
        if request.task is LLMTask.CLASSIFY:
            text = self._classify(request)
            return self._response(text)
        if request.task is LLMTask.SUMMARIZE:
            return self._response(self._summarize(request))
        return self._agent(request)

    @staticmethod
    def _response(text: str, calls: tuple[ToolCall, ...] = ()) -> LLMResponse:
        return LLMResponse(
            text=text,
            tool_calls=calls,
            stop_reason=StopReason.TOOL_USE if calls else StopReason.END_TURN,
            usage=TokenUsage(),
            model="offline",
            provider="offline",
        )

    # --- classification ----------------------------------------------------------------------------
    def _classify(self, request: LLMRequest) -> str:
        text = str(
            request.metadata.get("customer_text")
            or unwrap_customer_message(request.messages[-1].text)
        )
        signals = detect_signals(text)
        result = self._rules.classify(text, signals)
        return json.dumps(
            {
                "intent": result.intent.name,
                "priority": result.priority.value,
                "sentiment": signals.sentiment.value,
                "confidence": result.confidence,
                "requires_tool": result.requires_tool,
                "requires_human": result.requires_human,
                "order_numbers": signals.order_numbers[:5],
                "language": "en",
                "summary": f"Customer request about {result.intent.name.replace('_', ' ')}.",
            }
        )

    @staticmethod
    def _summarize(request: LLMRequest) -> str:
        transcript = request.metadata.get("transcript") or []
        customer_lines = [str(text) for role, text in transcript if role == "customer"][-4:]
        references: list[str] = []
        for _, text in transcript:
            for values in detect_signals(str(text)).references.values():
                references.extend(values)
        summary = "Customer said: " + " | ".join(
            _first_sentences(line, 1, 140) for line in customer_lines
        )
        if references:
            summary += ". References mentioned: " + ", ".join(dict.fromkeys(references))
        return summary[:900]

    # --- agent ----------------------------------------------------------------------------------------
    def _agent(self, request: LLMRequest) -> LLMResponse:
        messages = request.messages
        turn_start = max(
            (i for i, m in enumerate(messages) if m.role == "user" and not m.tool_results),
            default=len(messages) - 1,
        )
        names: dict[str, str] = {}
        done: set[str] = set()
        for message in messages[turn_start:]:
            for call in message.tool_calls:
                names[call.id] = call.name
                done.add(f"{call.name}:{json.dumps(call.arguments, sort_keys=True)}")
        results: list[tuple[str, dict[str, Any]]] = []
        for message in messages[turn_start:]:
            for result in message.tool_results:
                try:
                    payload = json.loads(result.content)
                except ValueError:
                    payload = {"error": "unreadable"}
                if isinstance(payload, dict):
                    results.append((names.get(result.tool_call_id, "unknown"), payload))

        metadata = request.metadata
        intent = str(metadata.get("intent") or "general_question")
        references: dict[str, list[str]] = metadata.get("references") or {}
        customer_text = str(metadata.get("customer_text") or "")
        available = {tool.name for tool in request.tools}
        documents = messages[turn_start].documents if messages else ()

        planned = [
            (name, args)
            for name, args in self._plan(
                intent, references, customer_text, results, bool(documents)
            )
            if name in available and f"{name}:{json.dumps(args, sort_keys=True)}" not in done
        ]
        if planned:
            calls = tuple(
                ToolCall(id=f"offline_{uuid.uuid4().hex[:12]}", name=n, arguments=a)
                for n, a in planned[:3]
            )
            return self._response("", calls)
        notes = [str(n) for n in metadata.get("notes") or []]
        return self._response(self._compose(intent, results, documents, notes))

    @staticmethod
    def _plan(
        intent: str,
        references: dict[str, list[str]],
        text: str,
        results: list[tuple[str, dict[str, Any]]],
        have_documents: bool,
    ) -> list[tuple[str, dict[str, Any]]]:
        orders = references.get("order_number", [])[:2]
        tickets = references.get("ticket_number", [])[:1]
        skus = references.get("sku", [])[:2]
        lowered = text.lower()
        plan: list[tuple[str, dict[str, Any]]] = []
        if tickets:
            plan.append(("get_ticket_status", {"ticket_number": tickets[0]}))
        seen = {name for name, _ in results}
        if (
            not orders
            and not tickets
            and not skus
            and have_documents
            and _POLICY_QUESTION.search(lowered)
        ):
            return plan  # a general policy question: answer from the knowledge base

        if intent == "order_tracking":
            plan += [("get_order_status", {"order_number": o}) for o in orders] or [
                ("list_recent_orders", {"limit": 3})
            ]
        elif intent == "refund_request":
            if not orders:
                plan.append(("list_recent_orders", {"limit": 3}))
            for order in orders:
                if _REFUND_STATUS.search(lowered):
                    plan.append(("get_refund_status", {"order_number": order}))
                plan.append(("check_refund_eligibility", {"order_number": order}))
                eligible = any(
                    name == "check_refund_eligibility"
                    and r.get("order_number") == order
                    and r.get("eligible")
                    for name, r in results
                )
                if (
                    eligible
                    and _EXPLICIT_REFUND.search(lowered)
                    and not _REFUND_STATUS.search(lowered)
                ):
                    plan.append(
                        (
                            "request_refund",
                            {"order_number": order, "reason": _guess_reason(text), "note": None},
                        )
                    )
        elif intent == "payment_problem":
            plan += [("check_payment_status", {"order_number": o}) for o in orders] or [
                ("list_recent_orders", {"limit": 3})
            ]
        elif intent == "cancellation":
            if not orders:
                plan.append(("list_recent_orders", {"limit": 3}))
            for order in orders:
                tool = "cancel_order" if _EXPLICIT_CANCEL.search(lowered) else "get_order_status"
                plan.append((tool, {"order_number": order}))
        elif intent in ("product_question", "technical_problem"):
            plan += [("get_product_information", {"sku": s, "query": None}) for s in skus]
            if intent == "technical_problem" and not have_documents and len(text) >= 10:
                plan.append(
                    (
                        "create_support_ticket",
                        {
                            "subject": "Technical problem reported via chat",
                            "description": text[:1_500],
                        },
                    )
                )
        elif intent == "complaint" and len(text) >= 10:
            plan.append(
                (
                    "create_support_ticket",
                    {"subject": "Customer complaint", "description": text[:1_500]},
                )
            )
        return [(name, args) for name, args in plan if name not in seen or name == "request_refund"]

    @staticmethod
    def _compose(
        intent: str,
        results: list[tuple[str, dict[str, Any]]],
        documents: tuple[ContextDocument, ...],
        notes: list[str],
    ) -> str:
        parts: list[str] = []
        for name, data in results:
            if "error" in data:
                parts.append(str(data.get("message") or "I could not complete that lookup."))
                continue
            parts.append(_describe(name, data))
        parts = [p for p in parts if p]
        if documents and (
            not parts or intent in ("shipping_question", "general_question", "account_problem")
        ):
            # Documents arrive in authority order; only corroborating sources of the same kind are
            # added, so a secondary document can never contradict the primary one in the answer.
            primary = documents[0]
            for doc in [primary, *[d for d in documents[1:2] if d.category == primary.category]]:
                parts.append(f"From our {doc.title} [{doc.index}]: {_first_sentences(doc.text)}")
        if not parts:
            parts.append(
                "I'm sorry, I don't have reliable information to answer that. "
                "I can connect you with a member of our support team if you'd like."
            )
        if any("write actions are disabled" in note for note in notes):
            parts.append(
                "For changes to your orders, please ask me to connect you with a human agent."
            )
        return "\n\n".join(parts)


def _describe(name: str, data: dict[str, Any]) -> str:  # noqa: PLR0911, PLR0912 - one branch per tool
    if name == "get_order_status":
        sentences = [
            f"Order {data['order_number']} is currently {str(data['status']).replace('_', ' ')}."
        ]
        if data.get("delivered_on"):
            sentences.append(f"It was delivered on {data['delivered_on']}.")
        elif data.get("shipped_on"):
            sentences.append(f"It shipped on {data['shipped_on']}.")
        if data.get("estimated_delivery") and not data.get("delivered_on"):
            sentences.append(f"Estimated delivery: {data['estimated_delivery']}.")
        if data.get("carrier") and data.get("tracking_number"):
            sentences.append(
                f"Carrier: {data['carrier']}, tracking number {data['tracking_number']}."
            )
        items = ", ".join(f"{i['quantity']} x {i['name']}" for i in data.get("items", []))
        if items:
            sentences.append(f"Items: {items}.")
        return " ".join(sentences)
    if name == "list_recent_orders":
        orders = data.get("orders", [])
        if not orders:
            return "I could not find any orders on your account."
        lines = [
            f"- {o['order_number']} (placed {o['placed_on']}): {o['status']}, total {o['total']}"
            for o in orders
        ]
        return (
            "Here are your most recent orders:\n" + "\n".join(lines) + "\nWhich order do you mean?"
        )
    if name == "get_order_details":
        items = "; ".join(
            f"{i['quantity']} x {i['name']} at {i['unit_price']}" for i in data.get("items", [])
        )
        text = f"Order {data['order_number']} ({data['status']}): {items}. Total {data['total']}."
        payment = data.get("payment")
        if payment:
            text += f" Payment: {payment['status']} via {payment['method']}."
        return text
    if name == "check_payment_status":
        if not data.get("payment_status"):
            return f"I could not find a payment for order {data['order_number']}."
        text = f"The payment for order {data['order_number']} is {data['payment_status']} ({data['amount']}, {data['method']})."
        if data.get("failure_reason"):
            text += f" Reason: {data['failure_reason']}"
        if data.get("refunded_total") and not str(data["refunded_total"]).startswith("0.00"):
            text += f" Refunded so far: {data['refunded_total']}."
        return text
    if name == "check_refund_eligibility":
        if data.get("eligible"):
            text = f"Order {data['order_number']} is eligible for a refund of up to {data['max_refundable']}."
            if data.get("refund_window_ends_on"):
                text += f" The refund window ends on {data['refund_window_ends_on']}."
            return text
        return f"Order {data['order_number']} is not eligible for a refund. " + " ".join(
            data.get("reasons", [])
        )
    if name == "get_refund_status":
        refunds = data.get("refunds", [])
        if not refunds:
            return f"There are no refunds on order {data['order_number']} yet."
        lines = [
            f"- {r['refund_number']}: {r['amount']}, {r['status'].replace('_', ' ')}"
            for r in refunds
        ]
        return f"Refunds on order {data['order_number']}:\n" + "\n".join(lines)
    if name in ("request_refund", "cancel_order"):
        return (
            f"I've prepared this request: {data['summary']}. Nothing has changed yet - "
            "please review it and press Confirm in the app to submit it."
        )
    if name == "create_support_ticket":
        return (
            f"I've opened support ticket {data['ticket_number']} ({data['priority']} priority). "
            "Our team will follow up with you."
        )
    if name == "get_ticket_status":
        return f'Ticket {data["ticket_number"]} ("{data["subject"]}") is {str(data["status"]).replace("_", " ")}.'
    if name == "get_product_information":
        lines = [
            f"{p['name']} ({p['sku']}): {p['price']}, {p['availability']}, {p['warranty_months']}-month warranty. "
            f"{_first_sentences(p['description'], 1, 200)}"
            for p in data.get("products", [])
        ]
        return "\n".join(lines)
    if name == "get_customer_profile":
        return f"You are a {data['tier']} member with {data['order_count']} orders."
    if name == "request_human_agent":
        return str(data.get("message", ""))
    return ""
