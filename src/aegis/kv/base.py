"""Key-value store interface and key naming."""

from __future__ import annotations

import re
from typing import Protocol

from aegis.core.errors import DependencyUnavailable
from aegis.security.crypto import fingerprint

_SAFE_PART = re.compile(r"^[A-Za-z0-9._-]{1,64}$")


class KeyValueUnavailable(DependencyUnavailable):
    code = "cache_unavailable"


class KeyValueStore(Protocol):
    async def get(self, key: str) -> str | None: ...

    async def set(self, key: str, value: str, *, ttl_seconds: int) -> None: ...

    async def set_if_absent(self, key: str, value: str, *, ttl_seconds: int) -> bool: ...

    async def delete(self, key: str) -> None: ...

    async def delete_if_equals(self, key: str, expected: str) -> bool: ...

    async def incr(self, key: str, *, amount: int = 1, ttl_seconds: int) -> int:
        """Atomically add ``amount``; the TTL is applied when the key is first created."""
        ...

    async def ping(self) -> bool: ...

    async def close(self) -> None: ...


class KeyBuilder:
    """Namespaced keys: ``<prefix>:<env>:<kind>:<part>...``.

    Parts that are not short and simple (e-mail addresses, free text) are replaced by a
    fingerprint, so user input can neither inject key separators nor store PII in key names.
    """

    def __init__(self, prefix: str, env: str) -> None:
        self._root = f"{prefix}:{env}"

    def key(self, kind: str, *parts: str | int) -> str:
        safe = [p if _SAFE_PART.fullmatch(p := str(part)) else fingerprint(p) for part in parts]
        return ":".join((self._root, kind, *safe))
