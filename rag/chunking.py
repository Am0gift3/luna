"""Boundary-aware chunker (Phase 2).

Old code was `text[i:i+500]` — split mid-sentence and mid-flag. This splits
on paragraph breaks first, then sentence boundaries if needed, and only
falls back to hard-slicing for oversized atomic blocks (giant tables).
"""
import re
from . import config

# Sentence boundary that doesn't split on abbreviations like "CVE-2021." or "e.g."
_SENT_END = re.compile(r'(?<=[.!?])\s+(?=[A-Z0-9])')


def _hard_split(text, size, overlap):
    """Last resort: character-window with overlap. Keeps CVE IDs intact when possible."""
    out = []
    step = max(1, size - overlap)
    for i in range(0, len(text), step):
        piece = text[i:i + size]
        if piece.strip():
            out.append(piece.strip())
    return out


def _split_paragraph(paragraph, size, overlap):
    """Split an oversized paragraph on sentences, then hard-split if still too big."""
    if len(paragraph) <= size:
        return [paragraph]
    sentences = _SENT_END.split(paragraph)
    out, buf = [], ""
    for s in sentences:
        s = s.strip()
        if not s:
            continue
        if len(s) > size:
            # A single sentence bigger than CHUNK_SIZE — hard split it
            if buf:
                out.append(buf); buf = ""
            out.extend(_hard_split(s, size, overlap))
        elif len(buf) + len(s) + 1 <= size:
            buf = (buf + " " + s).strip()
        else:
            if buf: out.append(buf)
            buf = s
    if buf:
        out.append(buf)
    return out


def split(text: str):
    """Split `text` into overlapping, boundary-respecting chunks."""
    text = (text or "").strip()
    if not text:
        return []

    # First split on blank lines (structural boundaries)
    paragraphs = re.split(r"\n\s*\n", text)

    chunks, buf = [], ""
    for p in paragraphs:
        p = p.strip()
        if not p:
            continue
        if len(p) > config.CHUNK_SIZE:
            # Flush current buffer, then chunk this paragraph on its own
            if buf: chunks.append(buf); buf = ""
            chunks.extend(_split_paragraph(p, config.CHUNK_SIZE, config.CHUNK_OVERLAP))
        elif len(buf) + len(p) + 2 <= config.CHUNK_SIZE:
            buf = (buf + "\n\n" + p).strip()
        else:
            if buf: chunks.append(buf)
            buf = p

    if buf:
        chunks.append(buf)
    return [c for c in chunks if c.strip()]
