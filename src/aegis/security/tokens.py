"""Access tokens (short-lived JWTs) and opaque refresh / reset tokens.

Access tokens
    HS256-signed JWTs, 15 minutes by default. The decoder pins the algorithm (no ``alg=none``
    or RS/HS confusion), requires every claim, checks issuer, audience, expiry and token type,
    and caps the token length before parsing. A valid signature is necessary but not
    sufficient: the API additionally loads the session and user from the database on every
    request, so logout, password change, deactivation and role changes take effect at once.

Refresh and password-reset tokens
    256-bit random opaque strings. Only their SHA-256 digests are stored (a database leak does
    not yield usable tokens; the high entropy makes a salt unnecessary). Refresh tokens rotate
    on every use and re-use of a spent token revokes the whole session (theft detection).
"""

from __future__ import annotations

import hashlib
import secrets
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

import jwt

from aegis.core.errors import AuthenticationFailed
from aegis.core.time import Clock, utc_now
from aegis.domain.enums import Role

ALGORITHM = "HS256"
MAX_TOKEN_LENGTH = 2_048
_REQUIRED_CLAIMS = ("exp", "iat", "nbf", "iss", "aud", "sub", "sid", "jti", "typ", "role")


@dataclass(frozen=True, slots=True)
class AccessClaims:
    user_id: uuid.UUID
    session_id: uuid.UUID
    role: Role
    token_id: str
    issued_at: datetime
    expires_at: datetime


class TokenService:
    def __init__(
        self,
        *,
        secret: str,
        issuer: str,
        audience: str,
        access_ttl_seconds: int,
        clock: Clock = utc_now,
    ) -> None:
        self._secret = secret
        self._issuer = issuer
        self._audience = audience
        self._access_ttl = timedelta(seconds=access_ttl_seconds)
        self._clock = clock

    def issue_access_token(
        self, *, user_id: uuid.UUID, session_id: uuid.UUID, role: Role
    ) -> tuple[str, datetime]:
        now = self._clock().replace(microsecond=0)
        expires = now + self._access_ttl
        claims = {
            "iss": self._issuer,
            "aud": self._audience,
            "sub": str(user_id),
            "sid": str(session_id),
            "role": role.value,
            "typ": "access",
            "jti": secrets.token_urlsafe(16),
            "iat": now,
            "nbf": now,
            "exp": expires,
        }
        token = jwt.encode(claims, self._secret, algorithm=ALGORITHM)
        return token, expires

    def decode_access_token(self, token: str) -> AccessClaims:
        if not token or len(token) > MAX_TOKEN_LENGTH:
            raise AuthenticationFailed(log_message="access token missing or oversized")
        try:
            payload = jwt.decode(
                token,
                self._secret,
                algorithms=[ALGORITHM],
                audience=self._audience,
                issuer=self._issuer,
                leeway=10,
                options={"require": list(_REQUIRED_CLAIMS)},
            )
        except jwt.ExpiredSignatureError as exc:
            raise AuthenticationFailed(
                "Your session has expired.", log_message="access token expired"
            ) from exc
        except jwt.InvalidTokenError as exc:
            raise AuthenticationFailed(
                log_message=f"invalid access token: {type(exc).__name__}"
            ) from exc
        if payload.get("typ") != "access":
            raise AuthenticationFailed(log_message="token is not an access token")
        try:
            return AccessClaims(
                user_id=uuid.UUID(str(payload["sub"])),
                session_id=uuid.UUID(str(payload["sid"])),
                role=Role(str(payload["role"])),
                token_id=str(payload["jti"]),
                issued_at=_ts(payload["iat"]),
                expires_at=_ts(payload["exp"]),
            )
        except (ValueError, TypeError) as exc:
            raise AuthenticationFailed(log_message="access token claims malformed") from exc


def _ts(value: object) -> datetime:
    if isinstance(value, int | float):
        return datetime.fromtimestamp(value, tz=UTC)
    msg = "timestamp claim must be numeric"
    raise TypeError(msg)


def generate_opaque_token(nbytes: int = 32) -> str:
    return secrets.token_urlsafe(nbytes)


def hash_opaque_token(token: str) -> str:
    """Storage form of an opaque token (session, refresh, password-reset, MFA challenge).

    Only for values from :func:`generate_opaque_token` - 256 random bits, so a fast hash is the
    right construction: there is nothing to brute-force, and lookups stay constant-time in the
    index. Passwords never come here; they are hashed with Argon2id (:mod:`aegis.security.passwords`).
    """
    return hashlib.sha256(token.encode("utf-8")).hexdigest()
