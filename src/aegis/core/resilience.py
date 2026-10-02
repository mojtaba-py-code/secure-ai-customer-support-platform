"""Resilience primitives: a circuit breaker and retry with exponential backoff and jitter.

Retries are only ever applied to operations the caller declares idempotent (reads, embedding
calls, vector searches). Non-idempotent operations (creating tickets, refunds) are protected by
idempotency keys instead of blind retries.
"""

from __future__ import annotations

import asyncio
import enum
import logging
import random
import time
from collections.abc import Awaitable, Callable

from aegis.core.errors import DependencyUnavailable

logger = logging.getLogger(__name__)


class CircuitState(enum.StrEnum):
    CLOSED = "closed"
    OPEN = "open"
    HALF_OPEN = "half_open"


class CircuitOpenError(DependencyUnavailable):
    code = "circuit_open"


class CircuitBreaker:
    """Classic three-state breaker.

    * CLOSED: calls flow; consecutive failures are counted.
    * OPEN: calls are rejected immediately for ``reset_timeout`` seconds (fail fast instead of
      piling up timeouts against a dead dependency).
    * HALF_OPEN: one trial call is allowed; success closes the breaker, failure re-opens it.
    """

    def __init__(
        self,
        name: str,
        *,
        failure_threshold: int,
        reset_timeout: float,
        clock: Callable[[], float] = time.monotonic,
        on_state_change: Callable[[str, CircuitState], None] | None = None,
    ) -> None:
        if failure_threshold < 1:
            msg = "failure_threshold must be >= 1"
            raise ValueError(msg)
        self.name = name
        self._threshold = failure_threshold
        self._reset_timeout = reset_timeout
        self._clock = clock
        self._on_state_change = on_state_change
        self._state = CircuitState.CLOSED
        self._failures = 0
        self._opened_at = 0.0
        self._trial_in_flight = False

    @property
    def state(self) -> CircuitState:
        if (
            self._state is CircuitState.OPEN
            and self._clock() - self._opened_at >= self._reset_timeout
        ):
            self._transition(CircuitState.HALF_OPEN)
        return self._state

    def allow(self) -> bool:
        state = self.state
        if state is CircuitState.CLOSED:
            return True
        if state is CircuitState.HALF_OPEN and not self._trial_in_flight:
            self._trial_in_flight = True
            return True
        return False

    def record_success(self) -> None:
        self._failures = 0
        self._trial_in_flight = False
        if self._state is not CircuitState.CLOSED:
            self._transition(CircuitState.CLOSED)

    def record_failure(self) -> None:
        self._trial_in_flight = False
        if self._state is CircuitState.HALF_OPEN:
            self._open()
            return
        self._failures += 1
        if self._failures >= self._threshold:
            self._open()

    def release_trial(self) -> None:
        """Forget an in-flight half-open trial that ended without a verdict (e.g. cancellation)."""
        self._trial_in_flight = False

    def _open(self) -> None:
        self._opened_at = self._clock()
        self._transition(CircuitState.OPEN)

    def _transition(self, new_state: CircuitState) -> None:
        if new_state is self._state:
            return
        logger.warning(
            "circuit state change",
            extra={"event": "circuit.state", "circuit": self.name, "state": new_state.value},
        )
        self._state = new_state
        if self._on_state_change is not None:
            self._on_state_change(self.name, new_state)

    async def call[T](self, operation: Callable[[], Awaitable[T]]) -> T:
        if not self.allow():
            raise CircuitOpenError(log_message=f"circuit {self.name} is open")
        try:
            result = await operation()
        except Exception:
            self.record_failure()
            raise
        except BaseException:
            self.release_trial()
            raise
        self.record_success()
        return result


def backoff_delay(attempt: int, *, base: float, maximum: float, jitter: bool = True) -> float:
    """Exponential backoff (``base * 2**attempt``) capped at ``maximum``, with full jitter."""
    delay = min(maximum, base * (2.0**attempt))
    if jitter:
        # Full jitter spreads retries out; it is not a security-sensitive use of randomness.
        return random.uniform(0, delay)  # noqa: S311  # nosec B311
    return delay


async def retry_async[T](
    operation: Callable[[], Awaitable[T]],
    *,
    attempts: int,
    retry_on: tuple[type[BaseException], ...],
    base_delay: float = 0.2,
    max_delay: float = 2.0,
    sleep: Callable[[float], Awaitable[None]] = asyncio.sleep,
) -> T:
    """Run an *idempotent* operation, retrying only the listed transient exception types."""
    if attempts < 1:
        msg = "attempts must be >= 1"
        raise ValueError(msg)
    for attempt in range(attempts):
        try:
            return await operation()
        except retry_on as exc:
            if attempt == attempts - 1:
                raise
            delay = backoff_delay(attempt, base=base_delay, maximum=max_delay)
            logger.info(
                "retrying transient failure",
                extra={"event": "retry", "attempt": attempt + 1, "error": type(exc).__name__},
            )
            await sleep(delay)
    raise AssertionError("unreachable")  # pragma: no cover
