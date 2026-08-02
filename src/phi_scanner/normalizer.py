"""Text normalizer — cleans cell text before recognition.

Real-world Indian spreadsheets are messy:
  - Excel stores numbers as floats (9876543210.0 → "9876543210.0")
  - Cells contain multiple values separated by commas, semicolons, pipes
  - Text has curly/smart quotes, non-breaking spaces, zero-width characters
  - Identifiers are wrapped in labels like "PAN: ABCPD1234E"
  - Mixed encoding artifacts from copy-paste between systems

This module normalises cell text *before* it reaches the recognizers,
ensuring we don't miss identifiers hidden in real-world noise.

No PII is cached or stored — normalisation is a pure function.
"""
from __future__ import annotations

import re
import unicodedata


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

_EXCEL_FLOAT_PATTERN = re.compile(r"(?<![\d\.])(\d+)\.0(?!\d|\.)")


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
_CELL_DELIMITERS = re.compile(r"[,;\|/\\]+")

# But don't split if delimiters are inside a known identifier pattern.
# E.g., "27AAPFU0939F1ZV" should not be split on the slash.
# Strategy: only split if the delimiter is surrounded by whitespace or
# the resulting chunks are each >= 5 chars (not splitting mid-identifier).


def split_multi_value_cell(text: str) -> list[str]:
    """Split a cell that may contain multiple values into individual chunks.

    Returns the original text as the first element, followed by sub-chunks.
    Recognizers are run on ALL chunks (original + splits), so an identifier
    that spans a separator boundary is still caught by the original text pass.

    Examples:
      "PAN: ABCPD1234E, Mobile: 9876543210"
        → ["PAN: ABCPD1234E, Mobile: 9876543210",
           "PAN: ABCPD1234E", "Mobile: 9876543210"]

      "9876543210"  (no delimiters)
        → ["9876543210"]
    """
    chunks = [text]
    parts = _CELL_DELIMITERS.split(text)
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
    """Full normalisation pipeline: unicode → excel float → multi-value split.

    Returns a list of text chunks to be scanned. The first element is always
    the full normalised cell text; additional elements are sub-chunks from
    multi-value splitting.
    """
    text = normalise_unicode(text)
    text = normalise_excel_number(text)
    return split_multi_value_cell(text)
