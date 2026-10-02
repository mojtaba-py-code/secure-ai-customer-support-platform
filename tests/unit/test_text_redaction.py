from __future__ import annotations

import pytest

from aegis.security.redaction import (
    PiiKind,
    find_pii,
    iban_valid,
    luhn_valid,
    redact,
    redact_for_llm,
    redact_for_storage,
)
from aegis.security.text import (
    confusable_skeleton,
    count_invisible,
    detection_forms,
    has_mixed_scripts,
    normalize_text,
    truncate,
)

ZWSP = chr(0x200B)
RLO = chr(0x202E)
TAG_A = chr(0xE0041)
FULLWIDTH_A = chr(0xFF21)
CYRILLIC_A = chr(0x0430)


def test_normalize_removes_invisible_and_control_characters() -> None:
    raw = f"he{ZWSP}llo{RLO} wor{TAG_A}ld\x07\r\n\n\n\nnext"
    assert normalize_text(raw) == "hello world\n\nnext"


def test_normalize_folds_compatibility_characters() -> None:
    assert normalize_text(f"{FULLWIDTH_A}BC") == "ABC"


def test_count_invisible_detects_smuggling() -> None:
    assert count_invisible(f"a{ZWSP}b{TAG_A}c") == 2


def test_detection_forms_fold_homoglyphs_and_leetspeak() -> None:
    forms = detection_forms(f"1gn0re {CYRILLIC_A}ll")
    assert any("ignore all" in form for form in forms)
    assert confusable_skeleton(CYRILLIC_A) == "a"


def test_mixed_script_detection() -> None:
    assert has_mixed_scripts(f"p{CYRILLIC_A}ssword")
    assert not has_mixed_scripts("password")


def test_truncate() -> None:
    assert truncate("short", 10) == "short"
    assert truncate("x" * 50, 20).endswith("[truncated]")
    assert len(truncate("x" * 50, 20)) <= 20


@pytest.mark.parametrize(
    "number", ["4111 1111 1111 1111", "5500-0000-0000-0004", "340000000000009"]
)
def test_card_numbers_with_valid_luhn_are_redacted(number: str) -> None:
    result = redact_for_storage(f"my card is {number} thanks")
    assert number not in result.text
    assert result.counts == {"card": 1}


def test_luhn_invalid_numbers_are_kept() -> None:
    assert not luhn_valid("4111111111111112")
    assert redact("reference 4111 1111 1111 1112").text == "reference 4111 1111 1111 1112"


def test_order_numbers_dates_and_amounts_are_not_pii() -> None:
    text = "Order ORD-100231 was delivered on 2026-09-24 for 498.00 USD, ticket TCK-40718263"
    assert redact(text).text == text


def test_email_phone_ssn_iban_detection() -> None:
    text = "mail jane.doe@example.com call +1 555 010 2345 ssn 123-45-6789 iban GB82 WEST 1234 5698 7654 32"
    kinds = {m.kind for m in find_pii(text)}
    assert {PiiKind.EMAIL, PiiKind.PHONE, PiiKind.SSN, PiiKind.IBAN} <= kinds
    assert iban_valid("GB82WEST12345698765432")
    assert not iban_valid("GB00WEST12345698765432")


@pytest.mark.parametrize(
    "secret",
    [
        "sk-ant-api03-abcdefghijklmnopqrstuvwxyz012345",
        "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U",
        "Bearer abcdefghijklmnop1234567890",
        "postgresql://user:pw@10.0.0.5:5432/db",
        "password: hunter2!",
        "-----BEGIN PRIVATE KEY-----\nMIIE\n-----END PRIVATE KEY-----",
    ],
)
def test_secrets_are_redacted(secret: str) -> None:
    result = redact(f"here: {secret} end")
    assert "[REDACTED_SECRET]" in result.text


def test_plain_sentences_about_passwords_are_not_redacted() -> None:
    text = "My password is not working and my token is expired."
    assert redact(text).text == text


def test_storage_redaction_keeps_contact_details_but_llm_redaction_removes_them() -> None:
    text = "Email me at jane.doe@example.com, card 4111 1111 1111 1111"
    stored = redact_for_storage(text)
    assert "jane.doe@example.com" in stored.text
    assert "4111" not in stored.text
    for_model = redact_for_llm(text)
    assert "jane.doe@example.com" not in for_model.text
    assert "[REDACTED_EMAIL]" in for_model.text


def test_cvv_is_redacted() -> None:
    assert "123" not in redact_for_storage("the cvv is 123").text
