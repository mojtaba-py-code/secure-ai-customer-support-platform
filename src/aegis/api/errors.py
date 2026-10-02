"""Exception handlers: every error leaves as ``application/problem+json`` with a safe message.

* :class:`AegisError` -> its status and *public* message (the technical message is only logged);
* validation errors -> 422 listing field locations and messages but **never the submitted
  values** (FastAPI's default echoes the input, which would reflect passwords into responses
  and logs);
* framework HTTP errors (404, 405, 400) -> generic messages; a 405 lists every method the
  resource supports in ``Allow`` (RFC 9110, section 15.5.6).
"""

from __future__ import annotations

import logging
from typing import Any

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from starlette.exceptions import HTTPException as StarletteHTTPException
from starlette.responses import Response
from starlette.routing import Match

from aegis.core.errors import AegisError, AuthenticationFailed, RateLimited
from aegis.middleware.problem import problem_response

logger = logging.getLogger(__name__)

_GENERIC = {
    400: "The request could not be processed.",
    401: "Authentication required.",
    403: "You do not have permission to perform this action.",
    404: "The requested resource was not found.",
    405: "This method is not allowed for this resource.",
    413: "The request body is too large.",
    415: "The request content type is not supported.",
}
_METHODS = ("GET", "HEAD", "POST", "PUT", "PATCH", "DELETE")


async def handle_aegis_error(request: Request, exc: Exception) -> Response:
    if not isinstance(exc, AegisError):  # registered for AegisError only
        raise exc
    headers: dict[str, str] = {}
    if isinstance(exc, RateLimited):
        headers["Retry-After"] = str(exc.retry_after_seconds)
    if isinstance(exc, AuthenticationFailed):
        headers["WWW-Authenticate"] = 'Bearer realm="aegis-support"'
    level = logging.ERROR if exc.status_code >= 500 else logging.INFO
    logger.log(
        level,
        "request failed",
        extra={
            "event": "http.error",
            "code": exc.code,
            "status": exc.status_code,
            "reason": exc.log_message,
        },
    )
    return problem_response(
        exc.status_code,
        code=exc.code,
        detail=exc.public_message,
        headers=headers,
        details=exc.details,
    )


async def handle_validation_error(request: Request, exc: Exception) -> Response:
    if not isinstance(exc, RequestValidationError):  # registered for this type only
        raise exc
    errors: list[dict[str, Any]] = [
        {
            "loc": [str(part) for part in error.get("loc", ())][:6],
            "msg": str(error.get("msg", ""))[:200],
            "type": str(error.get("type", "")),
        }
        for error in list(exc.errors())[:20]
    ]
    return problem_response(
        422, code="validation_error", detail="The request is invalid.", errors=errors
    )


def allowed_methods(request: Request) -> str:
    """Every method some route serves for this path, for the ``Allow`` header of a 405.

    Starlette reports only the methods of the *first* route whose path matched, so a resource
    served by several routes (``GET`` and ``POST /api/v1/conversations``) would advertise a
    subset of its methods.
    """
    routes = request.app.router.routes
    return ", ".join(
        method
        for method in _METHODS
        if any(
            route.matches({**request.scope, "method": method})[0] is Match.FULL for route in routes
        )
    )


async def handle_http_error(request: Request, exc: Exception) -> Response:
    if not isinstance(exc, StarletteHTTPException):  # registered for this type only
        raise exc
    status = exc.status_code
    detail = _GENERIC.get(status, "The request could not be processed.")
    headers = dict(exc.headers or {}) if status < 500 else {}
    if status == 405 and (allow := allowed_methods(request)):
        headers["Allow"] = allow
    return problem_response(status, code=f"http_{status}", detail=detail, headers=headers)


def register_exception_handlers(app: FastAPI) -> None:
    app.add_exception_handler(AegisError, handle_aegis_error)
    app.add_exception_handler(RequestValidationError, handle_validation_error)
    app.add_exception_handler(StarletteHTTPException, handle_http_error)
