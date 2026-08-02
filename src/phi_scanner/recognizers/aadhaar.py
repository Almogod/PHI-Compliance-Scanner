"""Aadhaar recognizer with Verhoeff checksum validation.

Aadhaar number spec (UIDAI):
  - Exactly 12 decimal digits.
  - First digit is never 0 or 1 (UIDAI has not assigned those ranges).
  - The 12th digit is a Verhoeff check digit over the full 12-digit string.

Confidence tiers:
  HIGH   — 12-digit pattern + Verhoeff check passes.
  MEDIUM — 12-digit pattern matches but Verhoeff fails (possible transcription
            error; still worth human review per rules.md §14).

The Verhoeff algorithm is deterministic and public (Jacobus Verhoeff, 1969).
These tables are fixed constants, not a dependency.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from enum import Enum


# ---------------------------------------------------------------------------
# Verhoeff algorithm tables (fixed constants)
# ---------------------------------------------------------------------------

_D = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9],
    [1, 2, 3, 4, 0, 6, 7, 8, 9, 5],
    [2, 3, 4, 0, 1, 7, 8, 9, 5, 6],
    [3, 4, 0, 1, 2, 8, 9, 5, 6, 7],
    [4, 0, 1, 2, 3, 9, 5, 6, 7, 8],
    [5, 9, 8, 7, 6, 0, 4, 3, 2, 1],
    [6, 5, 9, 8, 7, 1, 0, 4, 3, 2],
    [7, 6, 5, 9, 8, 2, 1, 0, 4, 3],
    [8, 7, 6, 5, 9, 3, 2, 1, 0, 4],
    [9, 8, 7, 6, 5, 4, 3, 2, 1, 0],
]

_P = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9],
    [1, 5, 7, 6, 2, 8, 3, 0, 9, 4],
    [5, 8, 0, 3, 7, 9, 6, 1, 4, 2],
    [8, 9, 1, 6, 0, 4, 3, 5, 2, 7],
    [9, 4, 5, 3, 1, 2, 6, 8, 7, 0],
    [4, 2, 8, 6, 5, 7, 3, 9, 0, 1],
    [2, 7, 9, 3, 8, 0, 6, 4, 1, 5],
    [7, 0, 4, 6, 9, 1, 3, 2, 5, 8],
]

_INV = [0, 4, 3, 2, 1, 9, 8, 7, 6, 5]

# Matches 12-digit sequences not surrounded by other digits.
# First digit constrained to [2-9] per UIDAI assignment ranges.
_PATTERN = re.compile(r"(?<!\d)[2-9]\d{11}(?!\d)")

# Wider set of separators found in real Indian spreadsheets.
# Includes dots (2345.6789.0123), underscores, slashes, pipes, en/em dashes.
_SEPARATORS = re.compile(r"[\s\-\u2013\u2014\.\/_|]+")


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

class Confidence(str, Enum):
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"


@dataclass(frozen=True, slots=True)
class AadhaarMatch:
    raw_value: str
    masked_value: str   # first 8 digits replaced with XXXX XXXX
    confidence: Confidence
    start: int          # character offset within the scanned text
    end: int


def verhoeff_validate(number: str) -> bool:
    """Return True if *number* passes the Verhoeff check.

    The algorithm computes a running checksum c over digits processed
    right-to-left; a valid number yields c == 0.
    """
    c = 0
    for i, ch in enumerate(reversed(number)):
        c = _D[c][_P[i % 8][int(ch)]]
    return c == 0


def verhoeff_check_digit(prefix: str) -> str:
    """Return the Verhoeff check digit for an (n-1)-digit *prefix*.

    Finds the digit d in 0-9 such that verhoeff_validate(prefix + d) is True.
    Useful for generating synthetic valid numbers in the test corpus.
    """
    for d in range(10):
        if verhoeff_validate(prefix + str(d)):
            return str(d)
    raise ValueError(f"No valid Verhoeff check digit found for prefix {prefix!r}")


def _mask(value: str) -> str:
    return f"XXXX XXXX {value[-4:]}"


def _strip_phone_prefixes(text: str) -> str:
    """Remove common Indian phone prefixes so they don't create false Aadhaar matches.

    '+91XXXXXXXXXX' and '91XXXXXXXXXX' (after separator removal) would produce
    a 12-digit string starting with 9, which the Aadhaar pattern would match.
    Removing the country code before Aadhaar scanning eliminates this FP.
    """
    # Remove +91 or leading 91 when followed by exactly 10 digits (i.e., a mobile number)
    text = re.sub(r"\+91(?=\d{10}(?!\d))", "", text)
    text = re.sub(r"(?<!\d)91(?=[6-9]\d{9}(?!\d))", "", text)
    text = re.sub(r"(?<!\d)0(?=[6-9]\d{9}(?!\d))", "", text)  # trunk prefix
    return text


def find_aadhaar(text: str) -> list[AadhaarMatch]:
    """Return all Aadhaar candidates found in *text*, each with a confidence tier.

    Strips common separators (spaces, hyphens, dots, underscores, en-dashes)
    before matching so that formatted numbers in any common style are caught.
    Phone-number country-code prefixes (+91, 91) are removed first to prevent
    false positives from Indian mobile numbers.
    """
    results: list[AadhaarMatch] = []

    # Strip all common separators, then remove phone prefixes
    stripped = _SEPARATORS.sub("", text)
    stripped = _strip_phone_prefixes(stripped)

    for m in _PATTERN.finditer(stripped):
        raw = m.group()
        confidence = Confidence.HIGH if verhoeff_validate(raw) else Confidence.MEDIUM
        results.append(AadhaarMatch(
            raw_value=raw,
            masked_value=_mask(raw),
            confidence=confidence,
            start=m.start(),
            end=m.end(),
        ))
    return results
