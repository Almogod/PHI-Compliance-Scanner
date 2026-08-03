"""Text normalizer — cleans cell text before recognition.

Real-world Indian spreadsheets and unstructured documents are messy:
  - Excel stores numbers as floats (9876543210.0 → "9876543210.0")
  - Indic scripts use regional digits (e.g. Devanagari ०-९, Bengali ০-৯, Tamil ௦-௯)
  - Cells contain multiple values separated by commas, semicolons, pipes
  - Text has curly/smart quotes, non-breaking spaces, zero-width characters
  - Identifiers are wrapped in labels like "PAN: ABCPD1234E" or "आधार: १२३४..."
  - Mixed encoding artifacts from copy-paste between systems

Production hardening (v4.0):
  - Hard truncation gate: individual scan chunks are capped at MAX_CHUNK_LEN
    characters before being handed to any regex engine (ReDoS defence).
  - Indic / Regional numeral translation map (Devanagari, Bengali, Tamil, Gujarati, Telugu → ASCII digits).
"""
from __future__ import annotations

import re
import unicodedata

# Maximum characters passed to any individual regex recognizer call.
MAX_CHUNK_LEN: int = 512

# ---------------------------------------------------------------------------
# Indic / Regional numeral translation map
# ---------------------------------------------------------------------------

_INDIC_DIGIT_MAP: dict[int, int] = str.maketrans({
    # Devanagari (Hindi, Marathi, Nepali, Sanskrit)
    "०": "0", "१": "1", "२": "2", "३": "3", "४": "4",
    "५": "5", "६": "6", "७": "7", "८": "8", "९": "9",
    # Bengali / Assamese
    "০": "0", "১": "1", "২": "2", "৩": "3", "৪": "4",
    "৫": "5", "৬": "6", "৭": "7", "৮": "8", "৯": "9",
    # Gujarati
    "૦": "0", "૧": "1", "૨": "2", "૩": "3", "૪": "4",
    "૫": "5", "૬": "6", "૭": "7", "૮": "8", "૯": "9",
    # Tamil
    "௦": "0", "௧": "1", "௨": "2", "௩": "3", "௪": "4",
    "௫": "5", "௬": "6", "௭": "7", "௮": "8", "௯": "9",
    # Telugu
    "౦": "0", "౧": "1", "౨": "2", "౩": "3", "౪": "4",
    "౫": "5", "౬": "6", "౭": "7", "౮": "8", "౯": "9",
})

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
    """Strip invisible characters, normalise whitespace, and translate Indic numerals."""
    text = unicodedata.normalize("NFKC", text)
    text = text.translate(_INDIC_DIGIT_MAP)
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
    """Convert Excel float strings back to integer form."""
    return _EXCEL_FLOAT_PATTERN.sub(r"\1", text)


# ---------------------------------------------------------------------------
# Multi-value cell splitting
# ---------------------------------------------------------------------------

_CELL_DELIMITERS = re.compile(r"[,;|\\]+")
_SLASH_SPLIT = re.compile(r"(?<!\d)/(?!\d)")


def split_multi_value_cell(text: str) -> list[str]:
    """Split a cell that may contain multiple values into individual chunks."""
    chunks = [text]
    parts = _CELL_DELIMITERS.split(text)
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


def normalise_cell(text: str) -> list[str]:
    """Full normalisation pipeline: unicode → Indic translation → float cleanup → split."""
    text = normalise_unicode(text)
    text = normalise_excel_number(text)
    chunks = split_multi_value_cell(text)
    return [c[:MAX_CHUNK_LEN] for c in chunks]
