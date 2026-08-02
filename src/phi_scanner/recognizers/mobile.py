"""Mobile number recognizer for Indian numbering plan.

Indian mobile numbers (TRAI / DoT numbering plan):
  - 10 digits, first digit in {6, 7, 8, 9}.
  - Full E.164 form: +91 followed by 10 qualifying digits.
  - Common written forms: plain 10 digits, 0-prefixed (STD), +91-prefixed,
    91-prefixed, spaced/hyphenated.

No public checksum exists for mobile numbers. Confidence is therefore capped at
MEDIUM (rules.md §10 — identifiers without a checksum must never be HIGH).

v2 improvements:
  - Wider separator set (dots, underscores, slashes)
  - Handles parenthesised area codes: (91) 9876543210
  - Guards against 10-digit numeric strings that are clearly non-phone
    (amounts with currency symbols, timestamps, invoice numbers)
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from enum import Enum

# Valid first digits per DoT spectrum assignment (updated through 2024).
# Ranges 6xx, 7xx, 8xx, 9xx are all allocated to mobile services.
_VALID_FIRST_DIGITS: frozenset[str] = frozenset("6789")

# Wider separator set for normalisation
_SEPARATORS = re.compile(r"[\s\-\u2013\u2014\.\/_|()]+")

# Core 10-digit mobile pattern (not preceded/followed by a digit).
_PATTERN_BARE = re.compile(r"(?<!\d)([6-9]\d{9})(?!\d)")

# With country code variants: +91, 91, 0 prefix, with optional parens.
_PATTERN_CC = re.compile(
    r"(?<!\d)"
    r"(?:\+?91|0)"                # country code or trunk prefix
    r"[\s\-\.\(\)]*"             # optional separators including parens
    r"([6-9]\d{9})"              # 10-digit number
    r"(?!\d)"
)

# False-positive guards: currency symbols, common non-phone prefixes
_CURRENCY_PREFIX = re.compile(r"[₹$€£¥]|Rs\.?\s*|INR\s*", re.IGNORECASE)
_TIMESTAMP_PATTERN = re.compile(r"\d{4}[-/]\d{2}[-/]\d{2}")
_INVOICE_PATTERN = re.compile(r"(?:INV|ORD|REF|TXN|ID)[\-#:]?\s*\d", re.IGNORECASE)


class Confidence(str, Enum):
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"


@dataclass(frozen=True, slots=True)
class MobileMatch:
    raw_value: str          # as found in text (may include +91 prefix)
    normalised: str         # 10-digit form without country code
    masked_value: str       # XXXXXX followed by last 4 digits
    confidence: Confidence  # always MEDIUM — no checksum available
    start: int
    end: int


def _mask(digits10: str) -> str:
    return f"XXXXXX{digits10[-4:]}"


def _has_currency_context(text: str, match_start: int) -> bool:
    """Return True if the number is preceded by a currency symbol/prefix."""
    prefix = text[max(0, match_start - 10):match_start]
    return bool(_CURRENCY_PREFIX.search(prefix))


def _has_noise_context(text: str) -> bool:
    """Return True if the full text looks like a timestamp or invoice ref."""
    return bool(_TIMESTAMP_PATTERN.search(text) or _INVOICE_PATTERN.search(text))


def find_mobile(text: str) -> list[MobileMatch]:
    """Return all Indian mobile number candidates in *text*.

    Strips common separators (spaces, hyphens, dots, parens) before matching
    to catch formatted numbers like ``98765 43210`` or ``+91-9876543210``.

    v2: Guards against currency amounts, timestamps, and invoice numbers
    to reduce false positives on 10-digit numeric strings.
    """
    # Check context signals on the ORIGINAL text before stripping,
    # since stripped offsets don't correspond to original positions.
    has_currency = bool(_CURRENCY_PREFIX.search(text))
    has_noise = _has_noise_context(text)
    if has_currency or has_noise:
        return []

    results: list[MobileMatch] = []
    seen: set[str] = set()  # deduplicate by normalised 10-digit value

    stripped = _SEPARATORS.sub("", text)

    # Try country-code patterns first (more specific)
    for m in _PATTERN_CC.finditer(stripped):
        digits = m.group(1)
        if digits in seen:
            continue
        seen.add(digits)

        results.append(MobileMatch(
            raw_value=m.group(),
            normalised=digits,
            masked_value=_mask(digits),
            confidence=Confidence.MEDIUM,
            start=m.start(),
            end=m.end(),
        ))

    # Then bare 10-digit numbers
    for m in _PATTERN_BARE.finditer(stripped):
        digits = m.group(1)
        if digits in seen:
            continue
        seen.add(digits)

        results.append(MobileMatch(
            raw_value=digits,
            normalised=digits,
            masked_value=_mask(digits),
            confidence=Confidence.MEDIUM,
            start=m.start(),
            end=m.end(),
        ))

    return results


# ---------------------------------------------------------------------------
# BaseRecognizer adapter — auto-registers on import
# ---------------------------------------------------------------------------

from .base import BaseRecognizer, RecognizerMatch  # noqa: E402


class MobileRecognizer(BaseRecognizer):
    """Auto-registered BaseRecognizer adapter wrapping find_mobile()."""

    entity_type = "IN_MOBILE"

    def find(self, text: str) -> list[RecognizerMatch]:
        return [
            RecognizerMatch(
                entity_type="IN_MOBILE",
                raw_value=m.raw_value,
                masked_value=m.masked_value,
                confidence=m.confidence.value,
            )
            for m in find_mobile(text)
        ]


