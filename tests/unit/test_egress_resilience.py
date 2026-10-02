from __future__ import annotations

import asyncio
import json

import httpx2
import pytest

from aegis.core.egress import EgressPolicy, build_http_client, post_json
from aegis.core.errors import DependencyUnavailable, EgressDenied
from aegis.core.resilience import (
    CircuitBreaker,
    CircuitOpenError,
    CircuitState,
    backoff_delay,
    retry_async,
)

POLICY = EgressPolicy(["api.voyageai.com"])


@pytest.mark.parametrize(
    "url",
    [
        "http://api.voyageai.com/v1/embeddings",
        "https://evil.example.com/v1/embeddings",
        "https://169.254.169.254/latest/meta-data",
        "https://[::1]/x",
        "https://user:pw@api.voyageai.com/v1",
        "https://api.voyageai.com:8443/v1",
        "file:///etc/passwd",
        "https://api.voyageai.com.evil.example/v1",
        "https://api.voyageai.com/\r\nHost: evil",
    ],
)
def test_egress_policy_blocks_ssrf_vectors(url: str) -> None:
    with pytest.raises(EgressDenied):
        POLICY.validate(url)


def test_egress_policy_allows_allowlisted_https() -> None:
    assert POLICY.validate("https://API.voyageai.com./v1/embeddings")


def _client(handler: object) -> httpx2.AsyncClient:
    return httpx2.AsyncClient(transport=httpx2.MockTransport(handler), follow_redirects=False)  # type: ignore[arg-type]


async def test_post_json_success() -> None:
    def handler(request: httpx2.Request) -> httpx2.Response:
        assert json.loads(request.content) == {"a": 1}
        return httpx2.Response(200, json={"ok": True})

    async with _client(handler) as client:
        body = await post_json(
            client,
            POLICY,
            "https://api.voyageai.com/v1/x",
            payload={"a": 1},
            headers={},
            max_response_bytes=1_000,
        )
    assert body == {"ok": True}


@pytest.mark.parametrize(
    "response",
    [
        httpx2.Response(302, headers={"location": "http://169.254.169.254/"}),
        httpx2.Response(500, json={"error": "boom"}),
        httpx2.Response(200, text="<html>not json</html>", headers={"content-type": "text/html"}),
        httpx2.Response(200, content=b"{broken", headers={"content-type": "application/json"}),
        httpx2.Response(
            200,
            content=b'{"x": "' + b"a" * 5_000 + b'"}',
            headers={"content-type": "application/json"},
        ),
    ],
    ids=["redirect", "server-error", "wrong-content-type", "malformed", "oversized"],
)
async def test_post_json_rejects_bad_responses(response: httpx2.Response) -> None:
    async with _client(lambda request: response) as client:
        with pytest.raises(DependencyUnavailable):
            await post_json(
                client,
                POLICY,
                "https://api.voyageai.com/v1/x",
                payload={},
                headers={},
                max_response_bytes=1_000,
            )


async def test_post_json_refuses_non_allowlisted_url_before_connecting() -> None:
    calls = []

    def handler(request: httpx2.Request) -> httpx2.Response:
        calls.append(request)
        return httpx2.Response(200, json={})

    async with _client(handler) as client:
        with pytest.raises(EgressDenied):
            await post_json(
                client,
                POLICY,
                "https://evil.example/x",
                payload={},
                headers={},
                max_response_bytes=100,
            )
    assert calls == []


async def test_hardened_client_does_not_follow_redirects() -> None:
    client = build_http_client(timeout_seconds=5)
    assert client.follow_redirects is False
    await client.aclose()


def state_of(breaker: CircuitBreaker) -> CircuitState:
    """Read the state through a call so the type checker does not narrow it across steps."""
    return breaker.state


class FakeClock:
    def __init__(self) -> None:
        self.now = 0.0

    def __call__(self) -> float:
        return self.now


def test_circuit_breaker_lifecycle() -> None:
    clock = FakeClock()
    changes: list[CircuitState] = []
    breaker = CircuitBreaker(
        "t",
        failure_threshold=2,
        reset_timeout=10,
        clock=clock,
        on_state_change=lambda _, s: changes.append(s),
    )
    assert breaker.allow()
    breaker.record_failure()
    assert state_of(breaker) is CircuitState.CLOSED
    breaker.record_failure()
    assert state_of(breaker) is CircuitState.OPEN
    assert not breaker.allow()
    clock.now = 11
    assert state_of(breaker) is CircuitState.HALF_OPEN
    assert breaker.allow()
    assert not breaker.allow()  # only one trial at a time
    breaker.record_failure()
    assert state_of(breaker) is CircuitState.OPEN
    clock.now = 25
    assert breaker.allow()
    breaker.record_success()
    assert state_of(breaker) is CircuitState.CLOSED
    assert changes == [
        CircuitState.OPEN,
        CircuitState.HALF_OPEN,
        CircuitState.OPEN,
        CircuitState.HALF_OPEN,
        CircuitState.CLOSED,
    ]


async def test_circuit_breaker_call_and_cancellation() -> None:
    clock = FakeClock()
    breaker = CircuitBreaker("t", failure_threshold=1, reset_timeout=1, clock=clock)

    async def fail() -> None:
        raise RuntimeError("down")

    with pytest.raises(RuntimeError):
        await breaker.call(fail)
    with pytest.raises(CircuitOpenError):
        await breaker.call(fail)
    clock.now = 2

    async def cancelled() -> None:
        raise asyncio.CancelledError

    with pytest.raises(asyncio.CancelledError):
        await breaker.call(cancelled)
    assert breaker.allow()  # the interrupted trial did not wedge the breaker

    async def ok() -> str:
        return "ok"

    breaker.release_trial()
    assert await breaker.call(ok) == "ok"
    assert state_of(breaker) is CircuitState.CLOSED


def test_circuit_breaker_validates_threshold() -> None:
    with pytest.raises(ValueError, match="failure_threshold"):
        CircuitBreaker("t", failure_threshold=0, reset_timeout=1)


async def test_retry_async_retries_only_listed_errors() -> None:
    attempts: list[int] = []
    sleeps: list[float] = []

    async def flaky() -> str:
        attempts.append(1)
        if len(attempts) < 3:
            raise DependencyUnavailable
        return "done"

    async def fake_sleep(delay: float) -> None:
        sleeps.append(delay)

    assert (
        await retry_async(flaky, attempts=3, retry_on=(DependencyUnavailable,), sleep=fake_sleep)
        == "done"
    )
    assert len(sleeps) == 2

    async def broken() -> None:
        raise ValueError("not retried")

    with pytest.raises(ValueError, match="not retried"):
        await retry_async(broken, attempts=5, retry_on=(DependencyUnavailable,), sleep=fake_sleep)

    async def always_down() -> None:
        raise DependencyUnavailable

    with pytest.raises(DependencyUnavailable):
        await retry_async(
            always_down, attempts=2, retry_on=(DependencyUnavailable,), sleep=fake_sleep
        )
    with pytest.raises(ValueError, match="attempts"):
        await retry_async(always_down, attempts=0, retry_on=(DependencyUnavailable,))


def test_backoff_is_bounded() -> None:
    assert backoff_delay(10, base=0.2, maximum=2.0, jitter=False) == 2.0
    assert 0 <= backoff_delay(3, base=0.2, maximum=2.0) <= 1.6
