"""TOTP (RFC 6238) and recovery codes."""

from __future__ import annotations

import base64
from urllib.parse import parse_qs, urlsplit

import pytest

from aegis.security.totp import (
    STEP_SECONDS,
    current_step,
    generate_recovery_codes,
    generate_secret,
    hash_recovery_code,
    hotp,
    looks_like_recovery_code,
    normalize_recovery_code,
    provisioning_uri,
    verify_totp,
)

# The RFC 6238 appendix B key for HMAC-SHA1: the ASCII string "12345678901234567890".
RFC_SECRET = base64.b32encode(b"12345678901234567890").decode()


@pytest.mark.parametrize(
    ("unix_time", "expected"),
    [
        (59, "94287082"),
        (1_111_111_109, "07081804"),
        (1_111_111_111, "14050471"),
        (1_234_567_890, "89005924"),
        (2_000_000_000, "69279037"),
        (20_000_000_000, "65353130"),
    ],
)
def test_rfc_6238_test_vectors(unix_time: int, expected: str) -> None:
    assert hotp(RFC_SECRET, unix_time // STEP_SECONDS, digits=8) == expected


def test_secrets_are_random_160_bit_base32() -> None:
    first, second = generate_secret(), generate_secret()
    assert first != second
    assert len(first) == 32 and first.isalnum() and first.isupper()
    assert len(base64.b32decode(first)) == 20


def test_codes_are_accepted_within_one_step_of_drift() -> None:
    secret = generate_secret()
    now = 1_700_000_000.0
    step = current_step(now)
    for drift in (-1, 0, 1):
        assert verify_totp(secret, hotp(secret, step + drift), now=now) == step + drift
    for drift in (-2, 2):
        assert verify_totp(secret, hotp(secret, step + drift), now=now) is None


def test_used_steps_cannot_be_replayed() -> None:
    secret = generate_secret()
    now = 1_700_000_000.0
    step = current_step(now)
    code = hotp(secret, step)
    assert verify_totp(secret, code, now=now, last_step=step - 1) == step
    assert verify_totp(secret, code, now=now, last_step=step) is None  # the same code again
    assert verify_totp(secret, hotp(secret, step - 1), now=now, last_step=step) is None


@pytest.mark.parametrize("code", ["", "12345", "1234567", "12a456", "      ", "１２３４５６"])
def test_malformed_codes_are_rejected(code: str) -> None:
    assert verify_totp(generate_secret(), code, now=1_700_000_000.0) is None


def test_codes_with_spaces_are_accepted() -> None:
    secret = generate_secret()
    now = 1_700_000_000.0
    code = hotp(secret, current_step(now))
    assert verify_totp(secret, f"{code[:3]} {code[3:]}", now=now) is not None


def test_provisioning_uri() -> None:
    uri = provisioning_uri("JBSWY3DPEHPK3PXP", account="sam.rivera@acme.example", issuer="Aegis")
    parts = urlsplit(uri)
    assert parts.scheme == "otpauth" and parts.netloc == "totp"
    assert parts.path == "/Aegis:sam.rivera@acme.example"
    query = parse_qs(parts.query)
    assert query["secret"] == ["JBSWY3DPEHPK3PXP"]
    assert query["issuer"] == ["Aegis"]
    assert query["digits"] == ["6"] and query["period"] == ["30"]


def test_recovery_codes() -> None:
    codes = generate_recovery_codes()
    assert len(codes) == 10 and len(set(codes)) == 10
    for code in codes:
        assert len(code) == 19 and code.count("-") == 3
        assert looks_like_recovery_code(code)
        assert looks_like_recovery_code(code.upper().replace("-", " "))
    first = codes[0]
    assert hash_recovery_code(first) == hash_recovery_code(first.upper().replace("-", ""))
    assert normalize_recovery_code(" AB-cd ") == "abcd"
    assert not looks_like_recovery_code("123456")
    assert not looks_like_recovery_code("0000-0000-0000-0000")  # 0 is not in the alphabet
