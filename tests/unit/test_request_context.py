"""Client-address resolution: rate limits and the audit trail depend on it, so spoofing must fail."""

from __future__ import annotations

import httpx2
import pytest

from aegis.main import create_app
from aegis.middleware.request_context import Network, parse_networks, resolve_client_ip
from tests.conftest import build_container, make_settings

TRUSTED = parse_networks(["10.0.0.0/8", "192.168.1.10"])


@pytest.mark.parametrize(
    ("peer", "forwarded", "trusted", "expected"),
    [
        # Without configured proxies the header is ignored entirely.
        ("203.0.113.7", "1.2.3.4", [], "203.0.113.7"),
        # A direct client cannot claim another address: the peer is not a trusted proxy.
        ("203.0.113.7", "1.2.3.4", TRUSTED, "203.0.113.7"),
        # Right-most untrusted hop wins; the left-most entry is client-controlled.
        ("10.0.0.5", "1.2.3.4, 198.51.100.9", TRUSTED, "198.51.100.9"),
        # Trusted proxies inside the chain are skipped.
        ("10.0.0.5", "198.51.100.9, 10.0.0.7", TRUSTED, "198.51.100.9"),
        ("192.168.1.10", "198.51.100.9", TRUSTED, "198.51.100.9"),
        # Only proxies in the chain: fall back to the peer.
        ("10.0.0.5", "10.0.0.8", TRUSTED, "10.0.0.5"),
        # A malformed hop before any untrusted address: distrust the header.
        ("10.0.0.5", "198.51.100.9, garbage", TRUSTED, "10.0.0.5"),
        ("10.0.0.5", None, TRUSTED, "10.0.0.5"),
        ("10.0.0.5", "2001:db8::1", TRUSTED, "2001:db8::1"),
    ],
)
def test_resolve_client_ip(
    peer: str, forwarded: str | None, trusted: list[Network], expected: str
) -> None:
    assert resolve_client_ip(peer, forwarded, trusted) == expected


async def test_rate_limits_follow_the_real_client_behind_a_trusted_proxy() -> None:
    container = await build_container(
        make_settings(trusted_proxies="10.0.0.0/8", rl_api_per_ip_per_minute=2)
    )
    try:
        app = create_app(container.settings, container=container)
        proxy = httpx2.ASGITransport(app=app, client=("10.0.0.5", 443))
        async with httpx2.AsyncClient(transport=proxy, base_url="http://testserver") as http:

            async def status(client_ip: str) -> int:
                response = await http.get(
                    "/api/v1/auth/me", headers={"X-Forwarded-For": f"1.1.1.1, {client_ip}"}
                )
                return response.status_code

            first = [await status("198.51.100.1") for _ in range(3)]
            second = await status("198.51.100.2")
    finally:
        await container.close()
    assert first == [401, 401, 429]  # one real client is limited ...
    assert second == 401  # ... without affecting another client behind the same proxy


async def test_metrics_label_requests_with_the_full_route_template() -> None:
    """Labels are route templates (bounded cardinality), including the /api/v1 prefix."""
    container = await build_container(make_settings())
    try:
        app = create_app(container.settings, container=container)
        async with httpx2.AsyncClient(
            transport=httpx2.ASGITransport(app=app), base_url="http://testserver"
        ) as http:
            await http.get(f"/api/v1/orders/ORD-{'1' * 6}")
            await http.get("/health/live")
    finally:
        await container.close()
    from aegis.observability.metrics import render_metrics

    text = render_metrics().decode()
    assert 'route="/api/v1/orders/{order_number}"' in text
    assert 'route="/health/live"' in text
    assert "ORD-111111" not in text  # raw paths never become labels
