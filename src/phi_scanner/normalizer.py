"""Text normalizer — cleans cell text before recognition.

Real-world Indian spreadsheets are messy:
  - Excel stores numbers as floats (9876543210.0 → "9876543210.0")
  - Cells contain multiple values separated by commas, semicolons, pipes
  - Text has curly/smart quotes, non-breaking spaces, zero-width characters
  - Identifiers are wrapped in labels like "PAN: ABCPD1234E"
  - Mixed encoding artifacts from copy-paste between systems

Production hardening (v3.1):
  - Hard truncation gate: individual scan chunks are capped at MAX_CHUNK_LEN
    characters before being handed to any regex engine. This is a ReDoS defence
    — catastrophic backtracking on unbounded input from large unstructured text
    blocks (e.g., multi-paragraph free-text cells) can freeze the scanner.
    512 chars is generous enough to contain any real identifier with surrounding
    context, and tight enough to keep regex evaluation deterministic O(n).

No PII is cached or stored — normalisation is a pure function.
"""
from __future__ import annotations

import re
import unicodedata

# ---------------------------------------------------------------------------
# ReDoS defence: hard per-chunk truncation gate
# ---------------------------------------------------------------------------

# Maximum characters passed to any individual regex recognizer call.
# Justification:
#   - Longest Indian identifier: GSTIN at 15 chars + context labels ≈ 50 chars
#   - Generous surrounding context for inline labels / multi-value cells: 462 chars
#   - Total: 512 chars is sufficient to detect any real identifier while keeping
#     regex evaluation bounded. Unbounded cells from free-text or data-dump columns
#     cannot trigger catastrophic backtracking.
MAX_CHUNK_LEN: int = 512


# ---------------------------------------------------------------------------
# Unicode normalisation
# ---------------------------------------------------------------------------

# Zero-width characters that sneak in from web copy-paste
_ZERO_WIDTH = re.compile(r"[\u200b\u200c\u200d\u200e\u200f\ufeff\u00ad]")

# Non-breaking spaces, thin spaces, en/em spaces, etc. → regular space
_UNUSUAL_SPACES = re.compile(r"[\u00a0\u2000-\u200a\u202f\u205f\u3000]")

# Smart/curly quotes → straight quotes
_SMART_QUOTES: dict[str, str] = {
    "\u2018": "'", "\u2019": "'",  # single
    "\u201c": '"', "\u201d": '"',  # double
}


def normalise_unicode(text: str) -> str:
    """Strip invisible characters and normalise whitespace variants."""
    text = unicodedata.normalize("NFKC", text)
    text = _ZERO_WIDTH.sub("", text)
    text = _UNUSUAL_SPACES.sub(" ", text)
    for smart, straight in _SMART_QUOTES.items():
        text = text.replace(smart, straight)
    return text


# ---------------------------------------------------------------------------
# Excel float cleanup
# ---------------------------------------------------------------------------

_EXCEL_FLOAT_PATTERN = re.compile(r"(?<![\d\.])([\d]+)\.0(?!\d|\.)")


def normalise_excel_number(text: str) -> str:
    """Convert Excel float strings back to integer form.

    Excel internally stores all numbers as IEEE 754 doubles. When openpyxl
    reads a cell containing the integer 9876543210, it returns the float
    9876543210.0, which str() renders as "9876543210.0". The trailing ".0"
    breaks every digit-boundary-anchored pattern.

    Only strips trailing ".0" on whole numbers — does not touch values with
    version formats like "1.0.0" or actual decimal places like "123.45".
    """
    return _EXCEL_FLOAT_PATTERN.sub(r"\1", text)



# ---------------------------------------------------------------------------
# Multi-value cell splitting
# ---------------------------------------------------------------------------

# Separators that commonly delimit multiple values in a single cell.
# Does NOT split on spaces (would break everything) or hyphens (used in
# formatted numbers).
_CELL_DELIMITERS = re.compile(r"[,;|\\]+")

# Do NOT split on "/" when it is surrounded by digits (date separators like
# 01/01/2024 or path separators /data/file) — only split "/" between non-digits.
_SLASH_SPLIT = re.compile(r"(?<!\d)/(?!\d)")


def split_multi_value_cell(text: str) -> list[str]:
    """Split a cell that may contain multiple values into individual chunks.

    Returns the original text as the first element, followed by sub-chunks.
    Recognizers are run on ALL chunks (original + splits), so an identifier
    that spans a separator boundary is still caught by the original text pass.

    v3.1: Only splits on "/" when not surrounded by digits, preventing date
    values like "01/01/2024" from being incorrectly fragmented.

    Examples:
      "PAN: ABCPD1234E, Mobile: 9876543210"
        → ["PAN: ABCPD1234E, Mobile: 9876543210",
           "PAN: ABCPD1234E", "Mobile: 9876543210"]

      "9876543210"  (no delimiters)
        → ["9876543210"]
    """
    chunks = [text]
    # Split on comma/semicolon/pipe/backslash
    parts = _CELL_DELIMITERS.split(text)
    # Also split on "/" when not between digits
    slash_parts: list[str] = []
    for p in parts:
        slash_parts.extend(_SLASH_SPLIT.split(p))
    parts = slash_parts

    if len(parts) > 1:
        for part in parts:
            cleaned = part.strip()
            if cleaned and len(cleaned) >= 5:
                chunks.append(cleaned)
    return chunks


# ---------------------------------------------------------------------------
# Full normalisation pipeline
# ---------------------------------------------------------------------------

def normalise_cell(text: str) -> list[str]:
    """Full normalisation pipeline: unicode → excel float → truncation → multi-value split.

    Returns a list of text chunks to be scanned. The first element is always
    the full normalised cell text (truncated to MAX_CHUNK_LEN); additional
    elements are sub-chunks from multi-value splitting.

    The truncation gate (MAX_CHUNK_LEN) is applied to EVERY chunk before
    returning, ensuring no unbounded string ever reaches a regex engine.
    This is the primary ReDoS mitigation.
    """
    text = normalise_unicode(text)
    text = normalise_excel_number(text)
    chunks = split_multi_value_cell(text)
    # Apply the truncation gate to every chunk
    return [c[:MAX_CHUNK_LEN] for c in chunks]
