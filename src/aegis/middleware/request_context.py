"""Request correlation, client-address resolution, access logging and HTTP metrics.

Client IP: ``X-Forwarded-For`` is honoured only when the direct peer is a configured trusted
proxy, and then the right-most address that is *not* a trusted proxy is used (the left-most
entries are client-controlled and trivially spoofed). Without trusted proxies the header is
ignored. Rate limiting and audit records rely on this value, so getting it wrong would let an
attacker rotate their apparent IP at will.
"""

from __future__ import annotations

import ipaddress
import logging
import time
from collections.abc import Sequence

from starlette.datastructures import Headers, MutableHeaders
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from aegis.core.context import client_ip_var, request_id_var, sanitize_request_id, user_id_var
from aegis.observability import metrics

logger = logging.getLogger("aegis.access")

Network = ipaddress.IPv4Network | ipaddress.IPv6Network


def parse_networks(values: Sequence[str]) -> list[Network]:
    return [ipaddress.ip_network(v.strip(), strict=False) for v in values if v.strip()]


def _in_networks(address: str, networks: Sequence[Network]) -> bool:
    try:
        ip = ipaddress.ip_address(address)
    except ValueError:
        return False
    return any(ip in network for network in networks)


def resolve_client_ip(peer: str, forwarded_for: str | None, trusted: Sequence[Network]) -> str:
    if not trusted or not forwarded_for or not _in_networks(peer, trusted):
        return peer
    chain = [part.strip() for part in forwarded_for.split(",") if part.strip()][-20:]
    for candidate in reversed(chain):
        try:
            ipaddress.ip_address(candidate)
        except ValueError:
            return peer
        if not _in_networks(candidate, trusted):
            return candidate
    return peer


class RequestContextMiddleware:
    def __init__(self, app: ASGIApp, *, trusted_proxies: Sequence[str] = ()) -> None:
        self.app = app
        self._trusted = parse_networks(trusted_proxies)

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        headers = Headers(scope=scope)
        request_id = sanitize_request_id(headers.get("x-request-id"))
        client = scope.get("client")
        peer = client[0] if client else "unknown"
        client_ip = resolve_client_ip(peer, headers.get("x-forwarded-for"), self._trusted)
        scope.setdefault("state", {})["client_ip"] = client_ip
        tokens = (
            request_id_var.set(request_id),
            client_ip_var.set(client_ip),
            user_id_var.set(None),
        )
        status = {"code": 500}
        started = time.perf_counter()

        async def send_wrapper(message: Message) -> None:
            if message["type"] == "http.response.start":
                status["code"] = message["status"]
                response_headers = MutableHeaders(scope=message)
                response_headers["X-Request-ID"] = request_id
            await send(message)

        try:
            await self.app(scope, receive, send_wrapper)
        finally:
            elapsed = time.perf_counter() - started
            route = scope.get("route")
            template = getattr(route, "path", None) or "unmatched"
            method = scope.get("method", "GET")
            metrics.HTTP_REQUESTS.labels(
                method=method, route=template, status=str(status["code"])
            ).inc()
            metrics.HTTP_LATENCY.labels(method=method, route=template).observe(elapsed)
            logger.info(
                "request",
                extra={
                    "event": "http.request",
                    "method": method,
                    "route": template,
                    "status": status["code"],
                    "duration_ms": round(elapsed * 1000, 1),
                },
            )
            for var, token in zip(
                (request_id_var, client_ip_var, user_id_var), tokens, strict=True
            ):
                var.reset(token)
