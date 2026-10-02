"""Last-resort error boundary.

Any exception that escapes the application becomes a generic RFC 9457 500 response carrying only
the request id - never the exception text, a stack trace, SQL or a hostname. The technical detail
is logged server-side. Sitting inside the header middleware, the 500 still carries the security
headers and the request id.
"""

from __future__ import annotations

import logging

from starlette.types import ASGIApp, Message, Receive, Scope, Send

from aegis.middleware.problem import problem_response

logger = logging.getLogger(__name__)


class ErrorBoundaryMiddleware:
    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        started = False

        async def tracking_send(message: Message) -> None:
            nonlocal started
            if message["type"] == "http.response.start":
                started = True
            await send(message)

        try:
            await self.app(scope, receive, tracking_send)
        except Exception:
            logger.exception("unhandled error", extra={"event": "http.unhandled_error"})
            if started:
                raise
            await problem_response(
                500,
                code="internal_error",
                detail="An unexpected error occurred. Please try again later.",
            )(scope, receive, send)
