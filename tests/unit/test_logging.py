"""Logging must never carry secrets or personal data - the redaction filter is the safety net."""

from __future__ import annotations

import json
import logging

import pytest

from aegis.core.context import request_id_var
from aegis.observability.logging import JsonFormatter, RedactionFilter, configure_logging
from aegis.observability.logging import _TextFormatter as TextFormatter

CARD = "4111 1111 1111 1111"
SECRET = "sk-ant-api03-abcdefghijklmnopqrstuvwxyz0123456789"


def make_record(message: str, *, extra: dict[str, object] | None = None) -> logging.LogRecord:
    record = logging.LogRecord("aegis.test", logging.INFO, __file__, 1, message, None, None)
    for key, value in (extra or {}).items():
        setattr(record, key, value)
    return record


def render(formatter: logging.Formatter, record: logging.LogRecord) -> str:
    assert RedactionFilter().filter(record)
    return formatter.format(record)


def test_json_log_lines_are_scrubbed() -> None:
    record = make_record(
        "payment by maya.thompson@example.com with card %s",
        extra={
            "event": "payment.test",
            "password": "hunter2-hunter2",
            "authorization": "Bearer abc.def.ghi",
            "details": {"token": "opaque-value", "note": f"key {SECRET}", "count": 3},
            "customer_phone": "+1 555 0101 234",
        },
    )
    record.args = (CARD,)
    line = json.loads(render(JsonFormatter(), record))
    assert line["event"] == "payment.test"
    assert "maya.thompson" not in line["msg"] and CARD not in line["msg"]
    assert "[REDACTED_EMAIL]" in line["msg"] and "[REDACTED_CARD]" in line["msg"]
    assert line["password"] == "[REDACTED]"
    assert line["authorization"] == "[REDACTED]"
    assert line["details"]["token"] == "[REDACTED]"
    assert SECRET not in json.dumps(line)
    assert line["details"]["count"] == 3
    assert line["customer_phone"] == "[REDACTED_PHONE]"  # scrubbed by content, not by key


def test_exceptions_are_logged_without_tracebacks() -> None:
    try:
        raise ValueError(f"lookup failed for maya.thompson@example.com using {SECRET}")
    except ValueError:
        import sys

        record = make_record("failure")
        record.exc_info = sys.exc_info()
    line = json.loads(render(JsonFormatter(), record))
    assert line["exc_type"] == "ValueError"
    assert "maya.thompson" not in line["exc"] and SECRET not in line["exc"]
    assert "Traceback" not in json.dumps(line)


def test_text_format_shows_scrubbed_extra_fields_and_request_id() -> None:
    token = request_id_var.set("req-123")
    try:
        record = make_record(
            "audit", extra={"event": "audit", "action": "auth.login", "api_key": "k-123456789"}
        )
        line = render(TextFormatter("%(levelname)s %(name)s: %(message)s"), record)
    finally:
        request_id_var.reset(token)
    assert line.startswith("INFO aegis.test: audit")
    assert "action=auth.login" in line and "event=audit" in line
    assert "api_key=[REDACTED]" in line and "k-123456789" not in line
    assert line.endswith("[req=req-123]")


def test_configure_logging_is_idempotent_and_quietens_noisy_libraries() -> None:
    root = logging.getLogger()
    before = list(root.handlers)
    try:
        configure_logging(level="INFO", json_output=True)
        configure_logging(level="INFO", json_output=False)
        ours = [h for h in root.handlers if getattr(h, "_aegis_handler", False)]
        assert len(ours) == 1
        assert isinstance(ours[0].formatter, TextFormatter)
        assert any(isinstance(f, RedactionFilter) for f in ours[0].filters)
        for noisy in ("httpx2", "anthropic", "qdrant_client"):
            assert logging.getLogger(noisy).level == logging.WARNING
    finally:
        for handler in list(root.handlers):
            if handler not in before:
                root.removeHandler(handler)
        for handler in before:
            if handler not in root.handlers:
                root.addHandler(handler)


@pytest.mark.parametrize("key", ["password", "new_password", "refresh_token", "cookie", "cvv"])
def test_sensitive_keys_are_replaced_wholesale(key: str) -> None:
    record = make_record("event", extra={key: "harmless-looking-value"})
    line = json.loads(render(JsonFormatter(), record))
    assert line[key] == "[REDACTED]"
