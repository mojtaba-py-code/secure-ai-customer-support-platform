"""Exception hierarchy.

Every error a user can see derives from :class:`AegisError` and carries a *public* message that
is safe to return (no hostnames, SQL, stack traces or identifiers of other customers). Technical
details go to ``log_message`` and are only logged server-side. Anything that is not an
``AegisError`` is treated as a bug and rendered as a generic 500 by the API layer.

``details`` are public too: they are returned to the client as structured data (for example the
reasons an order cannot be cancelled, or which password rules failed). Put only fixed codes and
policy texts there - never submitted values, secrets or other customers' data.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any, ClassVar


class AegisError(Exception):
    status_code: ClassVar[int] = 500
    code: ClassVar[str] = "internal_error"
    default_message: ClassVar[str] = "An unexpected error occurred. Please try again later."

    def __init__(
        self,
        public_message: str | None = None,
        *,
        log_message: str | None = None,
        details: Mapping[str, Any] | None = None,
    ) -> None:
        self.public_message = public_message or self.default_message
        self.log_message = log_message or self.public_message
        self.details: dict[str, Any] = dict(details or {})
        super().__init__(self.log_message)


class BadRequest(AegisError):
    status_code = 400
    code = "bad_request"
    default_message = "The request could not be processed."


class ValidationFailed(AegisError):
    status_code = 422
    code = "validation_error"
    default_message = "The request is invalid."


class AuthenticationFailed(AegisError):
    status_code = 401
    code = "authentication_failed"
    default_message = "Authentication failed."


class PermissionDenied(AegisError):
    status_code = 403
    code = "permission_denied"
    default_message = "You do not have permission to perform this action."


class NotFound(AegisError):
    status_code = 404
    code = "not_found"
    default_message = "The requested resource was not found."


class Conflict(AegisError):
    status_code = 409
    code = "conflict"
    default_message = "The request conflicts with the current state of the resource."


class PayloadTooLarge(AegisError):
    status_code = 413
    code = "payload_too_large"
    default_message = "The request body is too large."


class UnsupportedMediaType(AegisError):
    status_code = 415
    code = "unsupported_media_type"
    default_message = "The request content type is not supported."


class RateLimited(AegisError):
    status_code = 429
    code = "rate_limited"
    default_message = "Too many requests. Please slow down and try again shortly."

    def __init__(self, retry_after_seconds: int, public_message: str | None = None) -> None:
        super().__init__(public_message)
        self.retry_after_seconds = max(1, int(retry_after_seconds))


class BudgetExceeded(AegisError):
    status_code = 429
    code = "budget_exceeded"
    default_message = "The assistant has reached its usage limit for now. Please try again later."


class ServiceUnavailable(AegisError):
    status_code = 503
    code = "service_unavailable"
    default_message = "The service is temporarily unavailable. Please try again later."


class DependencyUnavailable(ServiceUnavailable):
    """An infrastructure dependency (database, cache, vector store, model API) failed."""

    code = "dependency_unavailable"


class EgressDenied(AegisError):
    """An outbound request was blocked by the egress policy (SSRF protection)."""

    status_code = 500
    code = "egress_denied"
