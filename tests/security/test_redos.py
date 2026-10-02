"""Regular-expression denial of service: every detector must stay fast on hostile input.

Catastrophic backtracking turns a 20 KB message into seconds or minutes of CPU per request. The
budget below is ~20x the measured time, so it only fails on super-linear behaviour.
"""

from __future__ import annotations

import time

import pytest

from aegis.agents.guard import OutputGuard
from aegis.security.injection import PromptInjectionDetector
from aegis.security.redaction import redact
from aegis.security.text import normalize_text

pytestmark = pytest.mark.security

PAYLOADS = {
    "repeated_words": "ignore " * 3_000,
    "single_char": "a" * 20_000,
    "image_openers": "![" * 8_000,
    "equals": "=" * 20_000,
    "digits": "1 " * 10_000,
    "zero_width": "ign\u200bore previous " * 1_500,
    "schemes": "https://" * 3_000,
    "brackets": "[" * 10_000 + "](" * 5_000,
    "at_signs": "a@" * 10_000,
    "money": "$1," * 7_000,
    "base64ish": "QUJD" * 5_000,
    "tags": "<a " * 7_000,
}


@pytest.mark.parametrize("name", sorted(PAYLOADS))
def test_detectors_stay_linear_on_hostile_input(name: str) -> None:
    payload = PAYLOADS[name]
    guard = OutputGuard(
        canary="AEGIS-CANARY",
        system_prompt="You are the support assistant for a store. " * 20,
        allowed_link_domains=["help.acme.example"],
        max_chars=2_500,
    )
    detector = PromptInjectionDetector()
    started = time.perf_counter()
    normalize_text(payload)
    detector.assess(payload)
    redact(payload)
    guard.check(payload, evidence=[payload[:1_000]], citation_count=2)
    assert time.perf_counter() - started < 3.0, name
