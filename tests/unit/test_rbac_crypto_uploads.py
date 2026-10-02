from __future__ import annotations

import pytest
from cryptography.fernet import Fernet

from aegis.core.errors import PayloadTooLarge, UnsupportedMediaType, ValidationFailed
from aegis.domain.enums import Role
from aegis.security import crypto
from aegis.security.crypto import DecryptionError, FieldCipher, derive_secret, fingerprint
from aegis.security.rbac import ROLE_PERMISSIONS, Permission, has_permission
from aegis.security.uploads import sanitize_filename, validate_upload

CUSTOMER_ONLY = {
    Permission.CONVERSATION_CREATE,
    Permission.MESSAGE_SEND,
    Permission.ACTION_CONFIRM_OWN,
    Permission.REFUND_REQUEST_OWN,
    Permission.ORDER_CANCEL_OWN,
}


def test_every_permission_is_granted_to_some_role() -> None:
    granted = set().union(*ROLE_PERMISSIONS.values())
    assert granted == set(Permission)


def test_role_hierarchy_for_staff() -> None:
    agent = ROLE_PERMISSIONS[Role.SUPPORT_AGENT]
    manager = ROLE_PERMISSIONS[Role.SUPPORT_MANAGER]
    admin = ROLE_PERMISSIONS[Role.ADMIN]
    assert agent < manager < admin


def test_staff_cannot_act_as_customers_and_customers_have_no_staff_rights() -> None:
    for role in (Role.SUPPORT_AGENT, Role.SUPPORT_MANAGER, Role.ADMIN):
        assert not CUSTOMER_ONLY & ROLE_PERMISSIONS[role]
    customer = ROLE_PERMISSIONS[Role.CUSTOMER]
    for permission in (
        Permission.ORDER_READ_ANY,
        Permission.KB_READ_INTERNAL,
        Permission.USER_MANAGE,
    ):
        assert permission not in customer
    assert not has_permission(Role.SUPPORT_AGENT, Permission.REFUND_DECIDE)
    assert has_permission(Role.SUPPORT_MANAGER, Permission.REFUND_DECIDE)


def test_field_cipher_roundtrip_and_tamper_detection() -> None:
    cipher = FieldCipher([Fernet.generate_key().decode()])
    token = cipher.encrypt("sensitive message")
    assert "sensitive" not in token
    assert cipher.decrypt(token) == "sensitive message"
    tampered = token[:-4] + ("AAAA" if not token.endswith("AAAA") else "BBBB")
    with pytest.raises(DecryptionError):
        cipher.decrypt(tampered)


def test_key_rotation() -> None:
    old, new = Fernet.generate_key().decode(), Fernet.generate_key().decode()
    legacy = FieldCipher([old]).encrypt("rotate me")
    rotating = FieldCipher([new, old])
    assert rotating.decrypt(legacy) == "rotate me"
    rotated = rotating.rotate(legacy)
    assert FieldCipher([new]).decrypt(rotated) == "rotate me"
    with pytest.raises(DecryptionError):
        FieldCipher([new]).decrypt(legacy)


def test_unconfigured_cipher_fails_closed(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(crypto._CipherHolder, "cipher", None)
    with pytest.raises(RuntimeError, match="not configured"):
        crypto.get_field_cipher()


def test_derived_secrets_are_stable_and_purpose_bound() -> None:
    assert derive_secret("master", "a") == derive_secret("master", "a")
    assert derive_secret("master", "a") != derive_secret("master", "b")
    assert len(fingerprint("x")) == 16


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("../../etc/passwd.md", "passwd.md"),
        ("..\\..\\windows\\system32\\evil.md", "evil.md"),
        ("C:\\Users\\x\\policy.MD", "policy.md"),
        ("con.md", "file_con.md"),
        ("../", "document"),
        ("refund policy (v2).md", "refund_policy_v2.md"),
        (None, "document"),
    ],
)
def test_filename_sanitisation(raw: str | None, expected: str) -> None:
    assert sanitize_filename(raw) == expected


def _upload(
    name: str, data: bytes, content_type: str = "text/markdown", limit: int = 10_000
) -> object:
    return validate_upload(
        filename=name, declared_content_type=content_type, data=data, max_bytes=limit
    )


def test_valid_markdown_upload() -> None:
    result = _upload("guide.md", "\ufeff# Guide\n\nUse the reset button for 10 seconds.".encode())
    assert result.safe_filename == "guide.md"  # type: ignore[attr-defined]
    assert result.text.startswith("# Guide")  # type: ignore[attr-defined]
    assert len(result.sha256) == 64  # type: ignore[attr-defined]


@pytest.mark.parametrize(
    ("name", "data", "content_type", "error"),
    [
        ("evil.exe", b"MZ\x90\x00 binary", "application/octet-stream", UnsupportedMediaType),
        ("policy.md.exe", b"# not really", "text/markdown", UnsupportedMediaType),
        ("report.pdf", b"%PDF-1.7 ...", "application/pdf", UnsupportedMediaType),
        ("fake.md", b"%PDF-1.7 pretending to be markdown", "text/markdown", UnsupportedMediaType),
        (
            "nul.md",
            b"# title\x00 with nul byte padding text",
            "text/markdown",
            UnsupportedMediaType,
        ),
        (
            "latin1.md",
            "caf\xe9 policy text here".encode("latin-1"),
            "text/markdown",
            ValidationFailed,
        ),
        ("empty.md", b"   \n  ", "text/markdown", ValidationFailed),
        ("tiny.md", b"# hi", "text/markdown", ValidationFailed),
        ("image.md", b"# a markdown doc with enough text", "image/png", UnsupportedMediaType),
    ],
)
def test_rejected_uploads(
    name: str, data: bytes, content_type: str, error: type[Exception]
) -> None:
    with pytest.raises(error):
        _upload(name, data, content_type)


def test_oversized_upload_rejected() -> None:
    with pytest.raises(PayloadTooLarge):
        _upload("big.md", b"# big\n" + b"x" * 20_000, limit=10_000)
