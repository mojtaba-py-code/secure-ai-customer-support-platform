"""Unicode normalisation for untrusted text.

Attackers hide instructions from humans (but not from models) with zero-width characters,
bidirectional overrides, Unicode "tag" characters (ASCII smuggling) and variation selectors,
and dodge keyword filters with homoglyphs (Cyrillic ``а`` for Latin ``a``) or leetspeak.

* :func:`normalize_text` is applied to every customer message and document before storage or
  use: NFKC folding, removal of invisible/format characters and control characters.
* :func:`detection_forms` produces extra *analysis-only* variants (confusable skeleton,
  de-leeted) that the injection detector scans; they are never stored or shown.
"""

from __future__ import annotations

import re
import unicodedata

_INVISIBLE_CODEPOINTS: frozenset[int] = frozenset(
    {
        0x00AD,  # soft hyphen
        0x034F,  # combining grapheme joiner
        0x061C,  # arabic letter mark
        0x115F,
        0x1160,  # hangul fillers
        0x17B4,
        0x17B5,
        0x180E,  # mongolian vowel separator
        0x200B,
        0x200C,
        0x200D,
        0x200E,
        0x200F,  # zero-width space/joiners, LRM/RLM
        0x202A,
        0x202B,
        0x202C,
        0x202D,
        0x202E,  # bidi embeddings / overrides
        0x2060,
        0x2061,
        0x2062,
        0x2063,
        0x2064,  # word joiner, invisible operators
        0x2066,
        0x2067,
        0x2068,
        0x2069,  # bidi isolates
        0x3164,  # hangul filler
        0xFEFF,  # zero-width no-break space / BOM
        0xFFA0,  # halfwidth hangul filler
    }
)


def _is_invisible(codepoint: int) -> bool:
    return (
        codepoint in _INVISIBLE_CODEPOINTS
        or 0xE0000 <= codepoint <= 0xE007F  # tag characters ("ASCII smuggling")
        or 0xFE00 <= codepoint <= 0xFE0F  # variation selectors
        or 0xE0100 <= codepoint <= 0xE01EF  # variation selectors supplement
    )


_MULTI_BLANK_LINES = re.compile(r"\n{3,}")
_TRAILING_SPACE = re.compile(r"[ \t]+\n")

# Confusables folded to Latin for *detection only*: Cyrillic and Greek letters that render
# identically to Latin ones in common fonts.
_CONFUSABLES = str.maketrans(
    {
        0x0430: "a",
        0x0435: "e",
        0x043E: "o",
        0x0440: "p",
        0x0441: "c",
        0x0443: "y",
        0x0445: "x",
        0x0456: "i",
        0x0458: "j",
        0x0455: "s",
        0x0501: "d",
        0x0261: "g",
        0x04BB: "h",
        0x0410: "a",
        0x0412: "b",
        0x0415: "e",
        0x041A: "k",
        0x041C: "m",
        0x041D: "h",
        0x041E: "o",
        0x0420: "p",
        0x0421: "c",
        0x0422: "t",
        0x0425: "x",
        0x03BF: "o",
        0x03B1: "a",
        0x03B5: "e",
        0x03B9: "i",
        0x03BA: "k",
        0x03BD: "v",
        0x03C1: "p",
        0x03C4: "t",
        0x03C5: "u",
        0x03C7: "x",
        0x039F: "o",
        0x0391: "a",
        0x0395: "e",
        0x0399: "i",
        0x039A: "k",
        0x03A1: "p",
        0x03A4: "t",
        0x03A7: "x",
    }
)
_LEET = str.maketrans(
    {"0": "o", "1": "i", "3": "e", "4": "a", "5": "s", "7": "t", "@": "a", "$": "s"}
)


def count_invisible(text: str) -> int:
    """Number of invisible/format characters (itself a signal of smuggling attempts)."""
    return sum(1 for ch in text if _is_invisible(ord(ch)))


def normalize_text(text: str) -> str:
    """Canonical, display-safe form of untrusted text.

    NFKC-folds compatibility characters (full-width letters, ligatures), removes invisible and
    control characters except newline and tab, normalises line endings, trims trailing spaces
    and collapses runs of blank lines.
    """
    folded = unicodedata.normalize("NFKC", text)
    folded = folded.replace("\r\n", "\n").replace("\r", "\n")
    kept: list[str] = []
    for ch in folded:
        cp = ord(ch)
        if _is_invisible(cp):
            continue
        if ch in "\n\t":
            kept.append(ch)
            continue
        category = unicodedata.category(ch)
        if category in ("Cc", "Cs", "Co", "Cn") or (category == "Cf"):
            continue
        kept.append(ch)
    cleaned = "".join(kept).replace("\t", "    ")
    cleaned = _TRAILING_SPACE.sub("\n", cleaned)
    cleaned = _MULTI_BLANK_LINES.sub("\n\n", cleaned)
    return cleaned.strip()


def confusable_skeleton(text: str) -> str:
    return text.translate(_CONFUSABLES)


def detection_forms(text: str) -> tuple[str, ...]:
    """Lower-cased variants used only for pattern detection (never persisted)."""
    base = normalize_text(text).lower()
    skeleton = confusable_skeleton(base)
    deleeted = skeleton.translate(_LEET)
    squashed = re.sub(r"[\s_*~`|]+", " ", deleeted)
    return tuple(dict.fromkeys((base, skeleton, deleeted, squashed)))


def has_mixed_scripts(word: str) -> bool:
    """True when one word mixes Latin letters with Cyrillic or Greek letters (homoglyph trick)."""
    scripts: set[str] = set()
    for ch in word:
        if not ch.isalpha():
            continue
        name = unicodedata.name(ch, "")
        if name.startswith("LATIN"):
            scripts.add("latin")
        elif name.startswith("CYRILLIC"):
            scripts.add("cyrillic")
        elif name.startswith("GREEK"):
            scripts.add("greek")
    return "latin" in scripts and len(scripts) > 1


def truncate(text: str, limit: int, *, marker: str = " [truncated]") -> str:
    if len(text) <= limit:
        return text
    return text[: max(0, limit - len(marker))].rstrip() + marker
