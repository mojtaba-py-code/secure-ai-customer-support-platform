"""Application-level encryption of sensitive columns and keyed derivations.

Conversation text, ticket descriptions, phone numbers, addresses and conversation summaries are
encrypted before they reach the database (Fernet: AES-128-CBC + HMAC-SHA256, authenticated).
A database dump, backup or replica therefore does not expose customer conversations.

Key rotation: ``AEGIS_FIELD_ENCRYPTION_KEYS`` is a comma-separated list; the first key encrypts,
all keys decrypt (``MultiFernet``). Add a new key in front, run ``aegis rotate-encryption``,
then drop the old key.

The cipher is configured once at process start (it must be reachable from the SQLAlchemy
column type, which has no dependency injection); using it before configuration fails closed.
"""

from __future__ import annotations

import hashlib
import hmac
from collections.abc import Sequence

from cryptography.fernet import Fernet, InvalidToken, MultiFernet


class DecryptionError(Exception):
    """Ciphertext could not be authenticated with any configured key."""


class FieldCipher:
    def __init__(self, keys: Sequence[str]) -> None:
        if not keys:
            msg = "at least one encryption key is required"
            raise ValueError(msg)
        self._multi = MultiFernet([Fernet(key.encode("ascii")) for key in keys])

    def encrypt(self, plaintext: str) -> str:
        return self._multi.encrypt(plaintext.encode("utf-8")).decode("ascii")

    def decrypt(self, token: str) -> str:
        try:
            return self._multi.decrypt(token.encode("ascii")).decode("utf-8")
        except (InvalidToken, UnicodeError, ValueError) as exc:
            raise DecryptionError("field ciphertext failed authentication") from exc

    def rotate(self, token: str) -> str:
        """Re-encrypt ``token`` under the primary key (no-op cost if already current)."""
        try:
            return self._multi.rotate(token.encode("ascii")).decode("ascii")
        except (InvalidToken, ValueError) as exc:
            raise DecryptionError("field ciphertext failed authentication") from exc


class _CipherHolder:
    cipher: FieldCipher | None = None


def configure_field_cipher(keys: Sequence[str]) -> FieldCipher:
    cipher = FieldCipher(keys)
    _CipherHolder.cipher = cipher
    return cipher


def get_field_cipher() -> FieldCipher:
    cipher = _CipherHolder.cipher
    if cipher is None:
        msg = "field encryption is not configured; call configure_field_cipher() at startup"
        raise RuntimeError(msg)
    return cipher


def generate_fernet_key() -> str:
    return Fernet.generate_key().decode("ascii")


def derive_secret(master: str, purpose: str, length: int = 16) -> str:
    """Deterministic, purpose-bound value derived from a master secret (HMAC-SHA256).

    Used for values that must be stable across restarts and replicas but must not reveal the
    master secret, e.g. the system-prompt canary.
    """
    digest = hmac.new(master.encode("utf-8"), purpose.encode("utf-8"), hashlib.sha256).hexdigest()
    return digest[:length]


def fingerprint(value: str) -> str:
    """Short, non-reversible fingerprint for logs (e.g. of an idempotency key or tool input)."""
    return hashlib.sha256(value.encode("utf-8")).hexdigest()[:16]
