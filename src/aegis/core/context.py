"""Request-scoped context (request id, acting user, client address) carried in ``ContextVar``s.

Log formatters and audit writers read these so that every log line and audit event of one
request can be correlated without threading the values through every function call.
"""

from __future__ import annotations

import re
import uuid
from contextvars import ContextVar

_SAFE_REQUEST_ID = re.compile(r"^[A-Za-z0-9._-]{8,64}$")

request_id_var: ContextVar[str | None] = ContextVar("aegis_request_id", default=None)
user_id_var: ContextVar[str | None] = ContextVar("aegis_user_id", default=None)
client_ip_var: ContextVar[str | None] = ContextVar("aegis_client_ip", default=None)


def new_request_id() -> str:
    return uuid.uuid4().hex


def sanitize_request_id(candidate: str | None) -> str:
    """Accept a caller-supplied request id only if it is short and harmless; else mint one.

    A client-controlled value ends up in logs and response headers, so anything that could
    inject log lines or header content is replaced.
    """
    if candidate and _SAFE_REQUEST_ID.fullmatch(candidate):
        return candidate
    return new_request_id()


def current_request_id() -> str | None:
    return request_id_var.get()
