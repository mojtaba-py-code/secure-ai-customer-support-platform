"""RFC 9457 problem responses shared by middleware and exception handlers."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from starlette.responses import JSONResponse

from aegis.core.context import current_request_id

PROBLEM_MEDIA_TYPE = "application/problem+json"

_TITLES = {
    400: "Bad Request",
    401: "Unauthorized",
    403: "Forbidden",
    404: "Not Found",
    405: "Method Not Allowed",
    409: "Conflict",
    413: "Content Too Large",
    415: "Unsupported Media Type",
    422: "Unprocessable Content",
    429: "Too Many Requests",
    500: "Internal Server Error",
    503: "Service Unavailable",
}


def problem_response(
    status: int,
    *,
    code: str,
    detail: str,
    headers: Mapping[str, str] | None = None,
    errors: list[dict[str, Any]] | None = None,
    details: Mapping[str, Any] | None = None,
) -> JSONResponse:
    body: dict[str, Any] = {
        "type": "about:blank",
        "title": _TITLES.get(status, "Error"),
        "status": status,
        "detail": detail,
        "code": code,
        "request_id": current_request_id(),
    }
    if errors:
        body["errors"] = errors
    if details:
        body["details"] = dict(details)
    return JSONResponse(
        body, status_code=status, headers=dict(headers or {}), media_type=PROBLEM_MEDIA_TYPE
    )
