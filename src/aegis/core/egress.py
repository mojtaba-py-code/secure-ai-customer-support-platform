"""Outbound HTTP policy (SSRF protection) and a hardened client factory.

The application never lets a model, a document or a user choose where the server connects:
outbound calls go only to provider hosts named in configuration, and every URL is checked
against an allowlist before a connection is opened. The client does not follow redirects
(a redirect is a classic SSRF pivot), verifies TLS, applies strict timeouts and refuses
oversized or non-JSON responses.
"""

from __future__ import annotations

import ipaddress
import json
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlsplit

import httpx2

from aegis.core.errors import DependencyUnavailable, EgressDenied

DEFAULT_USER_AGENT = "AegisSupport/1.0 (+https://support.acme.example)"


class EgressPolicy:
    """Allowlist of hosts the server may contact. Exact host match; HTTPS only."""

    def __init__(self, allowed_hosts: Iterable[str]) -> None:
        self._allowed = frozenset(h.strip().lower().rstrip(".") for h in allowed_hosts if h.strip())

    @property
    def allowed_hosts(self) -> frozenset[str]:
        return self._allowed

    def validate(self, url: str) -> str:
        """Return ``url`` if it may be requested, else raise :class:`EgressDenied`."""
        if len(url) > 2_048 or any(ord(ch) < 0x21 for ch in url):
            raise EgressDenied(log_message="egress URL rejected: length or control characters")
        parts = urlsplit(url)
        if parts.scheme != "https":
            raise EgressDenied(log_message=f"egress URL rejected: scheme {parts.scheme!r}")
        if parts.username or parts.password:
            raise EgressDenied(log_message="egress URL rejected: embedded credentials")
        host = (parts.hostname or "").lower().rstrip(".")
        if not host:
            raise EgressDenied(log_message="egress URL rejected: missing host")
        if _is_ip_literal(host):
            raise EgressDenied(log_message="egress URL rejected: IP literal hosts are not allowed")
        if host not in self._allowed:
            raise EgressDenied(log_message=f"egress URL rejected: host {host!r} not allowlisted")
        if parts.port not in (None, 443):
            raise EgressDenied(log_message="egress URL rejected: non-default port")
        return url


def _is_ip_literal(host: str) -> bool:
    try:
        ipaddress.ip_address(host.strip("[]"))
    except ValueError:
        return False
    return True


def build_http_client(*, timeout_seconds: float, max_connections: int = 20) -> httpx2.AsyncClient:
    """An ``httpx2.AsyncClient`` with secure defaults for provider APIs."""
    return httpx2.AsyncClient(
        follow_redirects=False,
        verify=True,
        timeout=httpx2.Timeout(timeout_seconds, connect=min(5.0, timeout_seconds)),
        limits=httpx2.Limits(max_connections=max_connections, max_keepalive_connections=10),
        headers={"User-Agent": DEFAULT_USER_AGENT},
    )


@dataclass(frozen=True, slots=True)
class ProviderResponse:
    status_code: int
    body: Any


async def send_request(
    client: httpx2.AsyncClient,
    policy: EgressPolicy,
    url: str,
    *,
    headers: Mapping[str, str],
    max_response_bytes: int,
    json_body: Mapping[str, Any] | None = None,
    form: Mapping[str, str] | None = None,
) -> ProviderResponse:
    """POST to an allowlisted URL; return the status and the decoded JSON body.

    2xx and 4xx answers are returned (a 4xx body explains a business refusal); everything else -
    transport failures, redirects, 5xx, non-JSON, oversized or malformed bodies - raises
    :class:`DependencyUnavailable` with a non-sensitive log message.
    """
    policy.validate(url)
    kwargs: dict[str, Any] = {"headers": dict(headers)}
    if json_body is not None:
        kwargs["json"] = dict(json_body)
    if form is not None:
        kwargs["data"] = dict(form)
    try:
        async with client.stream("POST", url, **kwargs) as resp:
            if resp.is_redirect:
                raise DependencyUnavailable(log_message=f"provider redirected ({resp.status_code})")
            if resp.status_code >= 500:
                raise DependencyUnavailable(
                    log_message=f"provider returned HTTP {resp.status_code}"
                )
            content_type = resp.headers.get("content-type", "").split(";")[0].strip().lower()
            if content_type != "application/json":
                raise DependencyUnavailable(log_message=f"unexpected content type {content_type!r}")
            declared = resp.headers.get("content-length")
            if declared is not None and declared.isdigit() and int(declared) > max_response_bytes:
                raise DependencyUnavailable(log_message="provider response exceeds size limit")
            body = bytearray()
            async for chunk in resp.aiter_bytes():
                body.extend(chunk)
                if len(body) > max_response_bytes:
                    raise DependencyUnavailable(log_message="provider response exceeds size limit")
            status_code = resp.status_code
    except httpx2.HTTPError as exc:
        raise DependencyUnavailable(
            log_message=f"provider transport error: {type(exc).__name__}"
        ) from exc
    try:
        return ProviderResponse(status_code, json.loads(bytes(body)))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise DependencyUnavailable(log_message="provider returned malformed JSON") from exc


async def post_json(
    client: httpx2.AsyncClient,
    policy: EgressPolicy,
    url: str,
    *,
    payload: Mapping[str, Any],
    headers: Mapping[str, str],
    max_response_bytes: int,
) -> Any:
    """POST JSON to an allowlisted URL and return the decoded JSON body of a 2xx answer.

    Any non-2xx answer (and every failure :func:`send_request` rejects) raises
    :class:`DependencyUnavailable`.
    """
    response = await send_request(
        client,
        policy,
        url,
        headers=headers,
        max_response_bytes=max_response_bytes,
        json_body=payload,
    )
    if response.status_code >= 400:
        raise DependencyUnavailable(log_message=f"provider returned HTTP {response.status_code}")
    return response.body
