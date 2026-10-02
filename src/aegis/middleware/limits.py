"""Request body size limits and content-type enforcement.

Size: a declared ``Content-Length`` over the limit is rejected before the body is read; a
streamed/chunked body is counted as it arrives and aborted as soon as it crosses the limit, so
an attacker cannot make the server buffer arbitrary amounts of data. Uploads have their own,
larger limit.

Content type: every body-carrying request must declare ``application/json`` (or
``multipart/form-data`` on upload routes). Besides cleaner errors, this blocks "simple" cross-site
form posts (``text/plain`` / urlencoded) at the door.
"""

from __future__ import annotations

from collections.abc import Sequence

from starlette.datastructures import Headers
from starlette.exceptions import HTTPException
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from aegis.middleware.problem import problem_response

_BODY_METHODS = frozenset({"POST", "PUT", "PATCH"})


class RequestTooLarge(HTTPException):
    def __init__(self) -> None:
        super().__init__(status_code=413, detail="The request body is too large.")


class BodySizeLimitMiddleware:
    def __init__(
        self,
        app: ASGIApp,
        *,
        default_limit: int,
        upload_limit: int,
        upload_paths: Sequence[str],
    ) -> None:
        self.app = app
        self._default = default_limit
        self._upload = upload_limit
        self._upload_paths = tuple(upload_paths)

    def _limit(self, path: str) -> int:
        return self._upload if path.startswith(self._upload_paths) else self._default

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http" or scope.get("method") not in _BODY_METHODS:
            await self.app(scope, receive, send)
            return
        limit = self._limit(str(scope.get("path", "")))
        declared = Headers(scope=scope).get("content-length")
        if declared is not None:
            if not declared.isdigit():
                await problem_response(
                    400, code="bad_request", detail="Invalid Content-Length header."
                )(scope, receive, send)
                return
            if int(declared) > limit:
                await problem_response(
                    413, code="payload_too_large", detail="The request body is too large."
                )(scope, receive, send)
                return

        received = 0
        started = False

        async def limited_receive() -> Message:
            nonlocal received
            message = await receive()
            if message["type"] == "http.request":
                received += len(message.get("body", b""))
                if received > limit:
                    raise RequestTooLarge
            return message

        async def tracking_send(message: Message) -> None:
            nonlocal started
            if message["type"] == "http.response.start":
                started = True
            await send(message)

        try:
            await self.app(scope, limited_receive, tracking_send)
        except RequestTooLarge:
            if started:
                raise
            await problem_response(
                413, code="payload_too_large", detail="The request body is too large."
            )(scope, receive, send)


class ContentTypeMiddleware:
    def __init__(self, app: ASGIApp, *, multipart_paths: Sequence[str]) -> None:
        self.app = app
        self._multipart_paths = tuple(multipart_paths)

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http" or scope.get("method") not in _BODY_METHODS:
            await self.app(scope, receive, send)
            return
        headers = Headers(scope=scope)
        has_body = headers.get("transfer-encoding") is not None or headers.get(
            "content-length", "0"
        ) not in ("", "0")
        if has_body:
            content_type = headers.get("content-type", "").split(";")[0].strip().lower()
            path = str(scope.get("path", ""))
            allowed = {"application/json"}
            if path.startswith(self._multipart_paths):
                allowed = {"multipart/form-data"}
            if content_type not in allowed:
                await problem_response(
                    415,
                    code="unsupported_media_type",
                    detail=f"Content-Type must be {' or '.join(sorted(allowed))}.",
                )(scope, receive, send)
                return
        await self.app(scope, receive, send)
