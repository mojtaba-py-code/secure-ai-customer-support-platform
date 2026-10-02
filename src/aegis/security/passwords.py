"""Password hashing (Argon2id) and password policy.

* Argon2id is memory-hard, so GPU/ASIC cracking of a stolen hash database is expensive.
  Parameters come from settings and old hashes are transparently upgraded on login
  (:meth:`PasswordHasher.needs_rehash`).
* Hashing is CPU- and memory-heavy (64 MiB per hash by default). The async wrappers run it in a
  worker thread so the event loop keeps serving requests, and a semaphore caps concurrent
  hashes so a login flood cannot exhaust memory.
* :meth:`PasswordHasher.verify_dummy` burns the same work for unknown accounts, so response
  timing does not reveal which e-mail addresses are registered.
* The policy follows NIST SP 800-63B: length over composition rules, a block-list of common
  passwords, no password that contains the account's e-mail name.
"""

from __future__ import annotations

import asyncio
import contextlib
import secrets

from argon2 import PasswordHasher as _Argon2Hasher
from argon2 import Type
from argon2.exceptions import InvalidHashError, VerificationError, VerifyMismatchError

MAX_PASSWORD_LENGTH = 128

COMMON_PASSWORDS: frozenset[str] = frozenset(
    [
        "123456",
        "123456789",
        "12345678",
        "password",
        "qwerty123",
        "qwerty",
        "1234567890",
        "111111",
        "1234567",
        "123123",
        "abc123",
        "password1",
        "iloveyou",
        "000000",
        "qwertyuiop",
        "1q2w3e4r",
        "654321",
        "password123",
        "admin",
        "admin123",
        "welcome",
        "welcome1",
        "letmein",
        "monkey",
        "dragon",
        "football",
        "baseball",
        "sunshine",
        "princess",
        "master",
        "shadow",
        "superman",
        "michael",
        "trustno1",
        "passw0rd",
        "starwars",
        "whatever",
        "freedom",
        "qazwsx",
        "zaq12wsx",
        "changeme",
        "changeme123",
        "administrator",
        "p@ssw0rd",
        "p@ssword",
        "secret123",
        "summer2024",
        "winter2024",
        "spring2025",
        "autumn2025",
        "summer2025",
        "winter2025",
        "summer2026",
        "welcome123",
        "letmein123",
        "passwordpassword",
        "correcthorsebatterystaple",
        "1qaz2wsx3edc",
        "qwerty12345",
        "11111111",
        "12341234",
        "aaaaaaaa",
        "asdfghjkl",
        "zxcvbnm123",
        "iloveyou123",
        "hello123",
        "hellohello",
        "loveyou123",
        "support123",
        "customer123",
        "acme123",
        "acmeacme123",
    ]
)


class PasswordHasher:
    def __init__(
        self,
        *,
        time_cost: int,
        memory_cost_kib: int,
        parallelism: int,
        max_concurrent: int = 4,
    ) -> None:
        self._hasher = _Argon2Hasher(
            time_cost=time_cost,
            memory_cost=memory_cost_kib,
            parallelism=parallelism,
            hash_len=32,
            salt_len=16,
            type=Type.ID,
        )
        self._dummy_hash = self._hasher.hash(secrets.token_urlsafe(24))
        self._semaphore = asyncio.Semaphore(max_concurrent)

    # --- synchronous core ------------------------------------------------------------------
    def hash(self, password: str) -> str:
        if len(password) > MAX_PASSWORD_LENGTH:
            msg = "password too long"
            raise ValueError(msg)
        return self._hasher.hash(password)

    def verify(self, stored_hash: str, password: str) -> bool:
        if len(password) > MAX_PASSWORD_LENGTH:
            self.verify_dummy(password[:MAX_PASSWORD_LENGTH])
            return False
        try:
            return self._hasher.verify(stored_hash, password)
        except VerifyMismatchError:
            return False
        except (VerificationError, InvalidHashError):
            return False

    def verify_dummy(self, password: str) -> None:
        with contextlib.suppress(VerificationError, InvalidHashError):
            self._hasher.verify(self._dummy_hash, password[:MAX_PASSWORD_LENGTH])

    def needs_rehash(self, stored_hash: str) -> bool:
        try:
            return self._hasher.check_needs_rehash(stored_hash)
        except InvalidHashError:
            return True

    # --- async wrappers (thread offload + concurrency cap) --------------------------------------------
    async def hash_async(self, password: str) -> str:
        async with self._semaphore:
            return await asyncio.to_thread(self.hash, password)

    async def verify_async(self, stored_hash: str, password: str) -> bool:
        async with self._semaphore:
            return await asyncio.to_thread(self.verify, stored_hash, password)

    async def verify_dummy_async(self, password: str) -> None:
        async with self._semaphore:
            await asyncio.to_thread(self.verify_dummy, password)


def password_policy_problems(
    password: str,
    *,
    min_length: int,
    email: str | None = None,
) -> list[str]:
    """Human-readable reasons a candidate password is rejected (empty list = acceptable)."""
    problems: list[str] = []
    if len(password) < min_length:
        problems.append(f"must be at least {min_length} characters long")
    if len(password) > MAX_PASSWORD_LENGTH:
        problems.append(f"must be at most {MAX_PASSWORD_LENGTH} characters long")
    lowered = password.lower()
    if lowered in COMMON_PASSWORDS or lowered.rstrip("!.?1") in COMMON_PASSWORDS:
        problems.append("is too common")
    if len(set(password)) < 5:
        problems.append("is too repetitive")
    if email:
        local = email.split("@", 1)[0].lower()
        if len(local) >= 4 and local in lowered:
            problems.append("must not contain your e-mail address")
    return problems
