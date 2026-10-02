"""Markdown-aware chunking.

Chunks follow the document's own structure: the text is split at headings first (each chunk
remembers its heading path, which becomes the citation "section"), then long sections are
packed paragraph by paragraph up to the size limit with a small overlap so a sentence that
straddles a boundary is still retrievable. A hard cap on chunks per document bounds the work a
single (possibly hostile) upload can cause.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

_HEADING = re.compile(r"^(#{1,6})\s+(.+?)\s*#*\s*$")


@dataclass(frozen=True, slots=True)
class Chunk:
    index: int
    section: str
    text: str


def _sections(markdown: str) -> list[tuple[str, str]]:
    """Split into (heading path, body) pairs; the path is e.g. ``Refund Policy > Eligibility``."""
    path: list[tuple[int, str]] = []
    current: list[str] = []
    sections: list[tuple[str, str]] = []

    def flush() -> None:
        body = "\n".join(current).strip()
        if body:
            sections.append((" > ".join(title for _, title in path), body))
        current.clear()

    for line in markdown.splitlines():
        match = _HEADING.match(line)
        if match:
            flush()
            level = len(match.group(1))
            while path and path[-1][0] >= level:
                path.pop()
            path.append((level, match.group(2).strip()[:120]))
            continue
        current.append(line)
    flush()
    return sections


def _split_long(paragraph: str, limit: int) -> list[str]:
    if len(paragraph) <= limit:
        return [paragraph]
    sentences = re.split(r"(?<=[.!?])\s+", paragraph)
    pieces: list[str] = []
    buffer = ""
    for sentence in sentences:
        rest = sentence
        while len(rest) > limit:
            pieces.append(rest[:limit])
            rest = rest[limit:]
        if buffer and len(buffer) + 1 + len(rest) > limit:
            pieces.append(buffer)
            buffer = rest
        else:
            buffer = f"{buffer} {rest}".strip()
    if buffer:
        pieces.append(buffer)
    return pieces


def chunk_markdown(
    markdown: str, *, max_chars: int, overlap_chars: int, max_chunks: int
) -> list[Chunk]:
    if overlap_chars >= max_chars:
        msg = "overlap must be smaller than the chunk size"
        raise ValueError(msg)
    chunks: list[Chunk] = []
    for section, body in _sections(markdown):
        paragraphs = [p.strip() for p in re.split(r"\n\s*\n", body) if p.strip()]
        units = [piece for p in paragraphs for piece in _split_long(p, max_chars)]
        buffer = ""
        for unit in units:
            if buffer and len(buffer) + 2 + len(unit) > max_chars:
                chunks.append(Chunk(len(chunks), section, buffer))
                tail = buffer[-overlap_chars:] if overlap_chars else ""
                if tail and " " in tail:
                    tail = tail[tail.index(" ") + 1 :]
                buffer = f"{tail}\n\n{unit}".strip() if tail else unit
                if len(buffer) > max_chars:
                    buffer = unit
            else:
                buffer = f"{buffer}\n\n{unit}".strip()
            if len(chunks) >= max_chunks:
                return chunks
        if buffer:
            chunks.append(Chunk(len(chunks), section, buffer))
        if len(chunks) >= max_chunks:
            return chunks[:max_chunks]
    return chunks
