"""Provider protocol and error taxonomy."""

from __future__ import annotations

from typing import Protocol

from aegis.core.errors import DependencyUnavailable
from aegis.llm.types import LLMRequest, LLMResponse


class LLMError(DependencyUnavailable):
    code = "llm_error"
    default_message = "The assistant is temporarily unavailable. Please try again shortly."


class LLMUnavailable(LLMError):
    """Transient provider failure (timeout, 429, 5xx, network) - counts against the breaker."""

    code = "llm_unavailable"


class LLMRequestRejected(LLMError):
    """The provider rejected the request (4xx): a configuration or programming error."""

    code = "llm_request_rejected"


class LLMProvider(Protocol):
    @property
    def name(self) -> str: ...

    async def complete(self, request: LLMRequest, *, model: str) -> LLMResponse: ...

    async def close(self) -> None: ...
