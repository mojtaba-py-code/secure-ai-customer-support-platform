"""Validation of knowledge-base uploads.

Nothing about an upload is trusted: not the filename, not the declared content type, not the
bytes. The accepted format is deliberately narrow - UTF-8 Markdown or plain text - because
parsers for rich formats (PDF, Office, HTML) are a large attack surface. Uploaded content is
stored in the database, never written to a path derived from the filename, so path traversal
is impossible by construction; the sanitised filename is display metadata only.
"""

from __future__ import annotations

import hashlib
import re
import unicodedata
from dataclasses import dataclass
from pathlib import PurePosixPath, PureWindowsPath

from aegis.core.errors import PayloadTooLarge, UnsupportedMediaType, ValidationFailed
from aegis.security.text import normalize_text

ALLOWED_EXTENSIONS: dict[str, str] = {
    ".md": "text/markdown",
    ".markdown": "text/markdown",
    ".txt": "text/plain",
}
ALLOWED_CONTENT_TYPES = frozenset(
    {"text/markdown", "text/x-markdown", "text/plain", "application/octet-stream", ""}
)
_WINDOWS_RESERVED = frozenset(
    {"con", "prn", "aux", "nul"}
    | {f"com{i}" for i in range(1, 10)}
    | {f"lpt{i}" for i in range(1, 10)}
)
_SAFE_CHARS = re.compile(r"[^A-Za-z0-9._-]+")
_MAGIC_SIGNATURES: tuple[bytes, ...] = (
    b"%PDF",
    b"PK\x03\x04",  # zip / docx / xlsx
    b"\x7fELF",
    b"MZ",  # windows executables
    b"\x89PNG",
    b"\xff\xd8\xff",  # jpeg
    b"GIF8",
    b"\x1f\x8b",  # gzip
    b"Rar!",
    b"7z\xbc\xaf",
    b"<?xml",
)
MAX_LINE_LENGTH = 10_000


@dataclass(frozen=True, slots=True)
class ValidatedUpload:
    safe_filename: str
    mime_type: str
    text: str
    sha256: str
    size_bytes: int


def sanitize_filename(raw: str | None) -> str:
    """Reduce an untrusted filename to a short, inert display name (``[A-Za-z0-9._-]``)."""
    name = unicodedata.normalize("NFKC", raw or "")
    # Strip any directory component in either path flavour ("../../x", "C:\\x", "/etc/x").
    name = PureWindowsPath(PurePosixPath(name).name).name
    name = _SAFE_CHARS.sub("_", name).strip("._")
    stem, dot, ext = name.rpartition(".")
    if not dot:
        stem, ext = name, ""
    stem = stem.strip("._-")
    if stem.lower() in _WINDOWS_RESERVED:
        stem = f"file_{stem}"
    stem = stem[:80] or "document"
    return f"{stem}.{ext.lower()}" if ext else stem


def validate_upload(
    *,
    filename: str | None,
    declared_content_type: str | None,
    data: bytes,
    max_bytes: int,
) -> ValidatedUpload:
    """Return the normalised document or raise a 4xx-mapped error explaining the rejection."""
    if len(data) > max_bytes:
        raise PayloadTooLarge(f"Documents must be at most {max_bytes // 1024} KiB.")
    if not data.strip():
        raise ValidationFailed("The document is empty.")

    safe_name = sanitize_filename(filename)
    extension = PurePosixPath(safe_name).suffix.lower()
    if extension not in ALLOWED_EXTENSIONS:
        raise UnsupportedMediaType(
            "Only Markdown (.md) and plain-text (.txt) documents are accepted."
        )
    content_type = (declared_content_type or "").split(";")[0].strip().lower()
    if content_type not in ALLOWED_CONTENT_TYPES:
        raise UnsupportedMediaType(
            "Only Markdown (.md) and plain-text (.txt) documents are accepted."
        )

    if data.startswith(_MAGIC_SIGNATURES):
        raise UnsupportedMediaType("The file content is not a text document.")
    if b"\x00" in data:
        raise UnsupportedMediaType("The file content is not a text document.")
    body = data.removeprefix(b"\xef\xbb\xbf")
    try:
        decoded = body.decode("utf-8", errors="strict")
    except UnicodeDecodeError as exc:
        raise ValidationFailed("Documents must be UTF-8 encoded text.") from exc

    control = sum(1 for ch in decoded if unicodedata.category(ch) == "Cc" and ch not in "\n\r\t")
    if control > max(8, len(decoded) // 1_000):
        raise UnsupportedMediaType("The file content is not a text document.")
    if any(len(line) > MAX_LINE_LENGTH for line in decoded.splitlines()):
        raise ValidationFailed("The document contains an overly long line.")

    text = normalize_text(decoded)
    if len(text) < 20:
        raise ValidationFailed("The document is too short to be useful.")
    return ValidatedUpload(
        safe_filename=safe_name,
        mime_type=ALLOWED_EXTENSIONS[extension],
        text=text,
        sha256=hashlib.sha256(text.encode("utf-8")).hexdigest(),
        size_bytes=len(data),
    )
