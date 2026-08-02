"""Mobile number recognizer for Indian numbering plan.

Indian mobile numbers (TRAI / DoT numbering plan):
  - 10 digits, first digit in {6, 7, 8, 9}.
  - Full E.164 form: +91 followed by 10 qualifying digits.
  - Common written forms: plain 10 digits, 0-prefixed (STD), +91-prefixed,
    91-prefixed, spaced/hyphenated.

No public checksum exists for mobile numbers. Confidence is therefore capped at
MEDIUM (rules.md §10 — identifiers without a checksum must never be HIGH).

False-positive risk:
  10-digit numbers starting with 6-9 are common in non-telephone contexts
  (order IDs, employee IDs, amounts). This recogniser uses boundary anchoring
  and validates the prefix range, but callers should weight mobile findings as
  weaker evidence than Aadhaar/PAN/GSTIN findings.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from enum import Enum

# Valid first digits per DoT spectrum assignment (updated through 2024).
# Ranges 6xx, 7xx, 8xx, 9xx are all allocated to mobile services.
_VALID_FIRST_DIGITS: frozenset[str] = frozenset("6789")

# Core 10-digit mobile pattern (not preceded/followed by a digit).
_PATTERN_BARE = re.compile(r"(?<!\d)([6-9]\d{9})(?!\d)")

# With country code variants: +91, 91, 0 prefix.
_PATTERN_CC = re.compile(
    r"(?<!\d)"
    r"(?:\+91|91|0)"            # country code or trunk prefix
    r"[\s\-]?"                  # optional separator
    r"([6-9]\d{9})"             # 10-digit number
    r"(?!\d)"
)


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


def find_mobile(text: str) -> list[MobileMatch]:
    """Return all Indian mobile number candidates in *text*.

    Strips common separators (spaces, hyphens) before matching to catch
    formatted numbers like ``98765 43210`` or ``+91-9876543210``.
    """
    results: list[MobileMatch] = []
    seen: set[int] = set()  # deduplicate by start position

    stripped = re.sub(r"[\s\-\u2013]+", "", text)

    for m in _PATTERN_CC.finditer(stripped):
        if m.start() in seen:
            continue
        seen.add(m.start())
        digits = m.group(1)
        results.append(MobileMatch(
            raw_value=m.group(),
            normalised=digits,
            masked_value=_mask(digits),
            confidence=Confidence.MEDIUM,
            start=m.start(),
            end=m.end(),
        ))

    for m in _PATTERN_BARE.finditer(stripped):
        if m.start() in seen:
            continue
        seen.add(m.start())
        digits = m.group(1)
        results.append(MobileMatch(
            raw_value=digits,
            normalised=digits,
            masked_value=_mask(digits),
            confidence=Confidence.MEDIUM,
            start=m.start(),
            end=m.end(),
        ))

    return results
