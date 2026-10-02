"""Time-based one-time passwords (RFC 6238) and recovery codes for two-factor authentication.

* TOTP with HMAC-SHA1, 30-second steps and 6 digits - the parameters every authenticator app
  supports. Secrets are 160 random bits (RFC 4226 recommends at least 128), base32-encoded for
  the provisioning URI, and stored encrypted by the caller.
* A code is accepted for the current step and one step either side (clock drift), and never for
  a step at or before the last one used - so an observed code cannot be replayed.
* Recovery codes carry 80 random bits (16 base32 characters), so a SHA-256 digest is enough to
  store them: brute-forcing a leaked digest is infeasible. Each code works once.

Standard library only; comparisons are constant-time.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import secrets
import struct
from urllib.parse import quote, urlencode

STEP_SECONDS = 30
DIGITS = 6
DRIFT_STEPS = 1
SECRET_BYTES = 20
RECOVERY_CODE_COUNT = 10
_RECOVERY_ALPHABET = "abcdefghijkmnpqrstuvwxyz23456789"  # no 0/o, 1/l: easy to read aloud


def generate_secret() -> str:
    """A new random TOTP secret, base32 without padding (32 characters)."""
    return base64.b32encode(secrets.token_bytes(SECRET_BYTES)).decode("ascii").rstrip("=")


def _key(secret: str) -> bytes:
    cleaned = secret.strip().replace(" ", "").upper()
    return base64.b32decode(cleaned + "=" * (-len(cleaned) % 8))


def hotp(secret: str, counter: int, *, digits: int = DIGITS) -> str:
    """RFC 4226 HOTP value for ``counter``."""
    digest = hmac.new(_key(secret), struct.pack(">Q", counter), hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    value = struct.unpack(">I", digest[offset : offset + 4])[0] & 0x7FFFFFFF
    return str(value % 10**digits).zfill(digits)


def current_step(now: float) -> int:
    return int(now) // STEP_SECONDS


def verify_totp(secret: str, code: str, *, now: float, last_step: int | None = None) -> int | None:
    """The matched time step if ``code`` is valid now, else ``None``.

    Steps at or before ``last_step`` are rejected (replay protection); the caller stores the
    returned step as the new ``last_step``.
    """
    candidate = code.strip().replace(" ", "")
    # isascii(): "isdigit" alone accepts full-width and other scripts' digits, which
    # compare_digest cannot compare.
    if len(candidate) != DIGITS or not (candidate.isascii() and candidate.isdigit()):
        return None
    step = current_step(now)
    matched: int | None = None
    for probe in range(step - DRIFT_STEPS, step + DRIFT_STEPS + 1):
        # Evaluate every candidate step so timing does not reveal which one matched.
        if hmac.compare_digest(hotp(secret, probe), candidate) and matched is None:
            matched = probe
    if matched is None or (last_step is not None and matched <= last_step):
        return None
    return matched


def provisioning_uri(secret: str, *, account: str, issuer: str) -> str:
    """``otpauth://`` URI for authenticator apps (usually shown as a QR code)."""
    label = quote(f"{issuer}:{account}", safe="@:")
    query = urlencode(
        {
            "secret": secret,
            "issuer": issuer,
            "algorithm": "SHA1",
            "digits": str(DIGITS),
            "period": str(STEP_SECONDS),
        }
    )
    return f"otpauth://totp/{label}?{query}"


def generate_recovery_codes(count: int = RECOVERY_CODE_COUNT) -> list[str]:
    """Single-use codes such as ``k3vq-8mzt-r2hx-9pwc`` (80 random bits each)."""
    codes = []
    for _ in range(count):
        raw = "".join(secrets.choice(_RECOVERY_ALPHABET) for _ in range(16))
        codes.append("-".join(raw[i : i + 4] for i in range(0, 16, 4)))
    return codes


def normalize_recovery_code(code: str) -> str:
    return "".join(ch for ch in code.strip().lower() if ch.isalnum())


def looks_like_recovery_code(code: str) -> bool:
    normalized = normalize_recovery_code(code)
    return len(normalized) == 16 and all(ch in _RECOVERY_ALPHABET for ch in normalized)


def hash_recovery_code(code: str) -> str:
    return hashlib.sha256(normalize_recovery_code(code).encode("ascii")).hexdigest()
