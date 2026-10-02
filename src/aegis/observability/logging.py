"""JSON logging with request correlation and defensive redaction.

Policy: code logs *events and identifiers*, never customer content (message text, addresses,
passwords, tokens). The :class:`RedactionFilter` is the safety net for mistakes: any extra field
whose name looks sensitive is replaced wholesale, and every string value is scrubbed for secrets
and personal data before it is formatted.
"""

from __future__ import annotations

import json
import logging
import sys
from datetime import UTC, datetime
from typing import Any

from aegis.core.context import client_ip_var, request_id_var, user_id_var
from aegis.security.redaction import redact

_SENSITIVE_KEY_PARTS = (
    "password",
    "passwd",
    "secret",
    "authorization",
    "cookie",
    "api_key",
    "apikey",
    "credential",
    "cvv",
    "ssn",
    "private_key",
)
_SENSITIVE_KEYS = frozenset(
    {
        "token",
        "access_token",
        "refresh_token",
        "reset_token",
        "id_token",
        "bearer",
        "content",
        "text",
        "body",
        "prompt",
        "message_text",
        "card",
        "card_number",
        "pan",
        "address",
        "phone",
    }
)
_STANDARD_ATTRS = frozenset(
    vars(logging.LogRecord("", 0, "", 0, "", None, None)).keys()
    | {"message", "asctime", "taskName"}
)
_MAX_VALUE_CHARS = 2_000


def _is_sensitive_key(key: str) -> bool:
    lowered = key.lower()
    return lowered in _SENSITIVE_KEYS or any(part in lowered for part in _SENSITIVE_KEY_PARTS)


def _scrub(value: Any, depth: int = 0) -> Any:
    if depth > 4:
        return "[depth-limit]"
    if isinstance(value, str):
        clipped = value[:_MAX_VALUE_CHARS]
        return redact(clipped).text
    if isinstance(value, dict):
        return {
            str(k): ("[REDACTED]" if _is_sensitive_key(str(k)) else _scrub(v, depth + 1))
            for k, v in value.items()
        }
    if isinstance(value, list | tuple | set | frozenset):
        return [_scrub(v, depth + 1) for v in list(value)[:50]]
    if isinstance(value, int | float | bool) or value is None:
        return value
    return _scrub(str(value), depth + 1)


class RedactionFilter(logging.Filter):
    """Scrubs the message and every extra attribute of a record in place."""

    def filter(self, record: logging.LogRecord) -> bool:
        try:
            message = record.getMessage()
        except (TypeError, ValueError):
            message = str(record.msg)
        record.msg = redact(message[:_MAX_VALUE_CHARS]).text
        record.args = None
        for key in list(vars(record)):
            if key in _STANDARD_ATTRS:
                continue
            value = getattr(record, key)
            setattr(record, key, "[REDACTED]" if _is_sensitive_key(key) else _scrub(value))
        return True


class JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        payload: dict[str, Any] = {
            "ts": datetime.fromtimestamp(record.created, tz=UTC).isoformat(timespec="milliseconds"),
            "level": record.levelname,
            "logger": record.name,
            "msg": record.getMessage(),
        }
        request_id = request_id_var.get()
        if request_id:
            payload["request_id"] = request_id
        user_id = user_id_var.get()
        if user_id:
            payload["user_id"] = user_id
        client_ip = client_ip_var.get()
        if client_ip:
            payload["client_ip"] = client_ip
        for key, value in vars(record).items():
            if key not in _STANDARD_ATTRS and key not in payload:
                payload[key] = value
        if record.exc_info and record.exc_info[0] is not None:
            # Exception type and a scrubbed message only: tracebacks can carry SQL parameters.
            exc_type, exc_value = record.exc_info[0], record.exc_info[1]
            payload["exc_type"] = exc_type.__name__
            payload["exc"] = redact(str(exc_value)[:_MAX_VALUE_CHARS]).text
        return json.dumps(payload, default=str, ensure_ascii=False)


class _TextFormatter(logging.Formatter):
    """Readable one-line format for development: message, extra fields (already scrubbed by the
    filter), request id. Production requires JSON (no tracebacks, see Settings)."""

    def format(self, record: logging.LogRecord) -> str:
        base = super().format(record)
        extras = " ".join(
            f"{key}={value}"
            for key, value in vars(record).items()
            if key not in _STANDARD_ATTRS and value not in (None, "", [], {})
        )
        request_id = request_id_var.get()
        return " ".join(
            part for part in (base, extras, request_id and f"[req={request_id}]") if part
        )


def configure_logging(*, level: str = "INFO", json_output: bool = True) -> None:
    """Install a single stdout handler with redaction on the root logger (idempotent)."""
    handler = logging.StreamHandler(sys.stdout)
    handler.addFilter(RedactionFilter())
    if json_output:
        handler.setFormatter(JsonFormatter())
    else:
        handler.setFormatter(_TextFormatter("%(asctime)s %(levelname)-7s %(name)s: %(message)s"))
    root = logging.getLogger()
    for existing in list(root.handlers):
        if getattr(existing, "_aegis_handler", False):
            root.removeHandler(existing)
    handler._aegis_handler = True  # type: ignore[attr-defined]  # marker for idempotency
    root.addHandler(handler)
    root.setLevel(level)
    # Libraries that log request details at INFO (URLs with query strings, headers) stay quiet.
    for noisy in (
        "httpx2",
        "httpcore2",
        "httpx",
        "httpcore",
        "anthropic",
        "qdrant_client",
        "urllib3",
    ):
        logging.getLogger(noisy).setLevel(logging.WARNING)
    logging.getLogger("uvicorn.access").disabled = True  # replaced by our access log
