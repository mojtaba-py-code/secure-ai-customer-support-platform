"""Verification of signed webhooks (Stripe's scheme).

A webhook endpoint is public by necessity, so the signature is the only thing that makes an event
trustworthy. Stripe signs ``"{timestamp}.{raw body}"`` with HMAC-SHA256 using the endpoint's
signing secret and sends ``Stripe-Signature: t=<timestamp>,v1=<hex>[,v1=<hex>...]``.

* the signature is checked over the *raw* bytes, before any JSON parsing;
* comparisons are constant-time; every ``v1`` value is tried (secret rotation sends two);
* the timestamp must be within the tolerance, so a captured request cannot be replayed later.
"""

from __future__ import annotations

import hashlib
import hmac

DEFAULT_TOLERANCE_SECONDS = 300
MAX_HEADER_LENGTH = 1_024


class WebhookSignatureError(ValueError):
    """The request is not a genuine, fresh webhook call."""


def stripe_signature(payload: bytes, secret: str, timestamp: int) -> str:
    signed = str(timestamp).encode("ascii") + b"." + payload
    return hmac.new(secret.encode("utf-8"), signed, hashlib.sha256).hexdigest()


def verify_stripe_signature(
    payload: bytes,
    header: str | None,
    secret: str,
    *,
    now: float,
    tolerance_seconds: int = DEFAULT_TOLERANCE_SECONDS,
) -> None:
    """Raise :class:`WebhookSignatureError` unless ``header`` signs ``payload`` recently."""
    if not header or len(header) > MAX_HEADER_LENGTH:
        msg = "missing or oversized signature header"
        raise WebhookSignatureError(msg)
    timestamp: int | None = None
    signatures: list[str] = []
    for part in header.split(","):
        key, _, value = part.strip().partition("=")
        if key == "t" and value.isascii() and value.isdigit():
            timestamp = int(value)
        elif key == "v1" and value:
            signatures.append(value)
    if timestamp is None or not signatures:
        msg = "malformed signature header"
        raise WebhookSignatureError(msg)
    if abs(now - timestamp) > tolerance_seconds:
        msg = "timestamp outside the tolerance"
        raise WebhookSignatureError(msg)
    expected = stripe_signature(payload, secret, timestamp)
    if not any(
        candidate.isascii() and hmac.compare_digest(expected, candidate) for candidate in signatures
    ):
        msg = "signature mismatch"
        raise WebhookSignatureError(msg)
