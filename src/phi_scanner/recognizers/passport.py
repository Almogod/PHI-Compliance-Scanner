"""Indian Passport Number recognizer.

Indian Passport spec (Ministry of External Affairs):
  - Exactly 8 characters.
  - 1st character is an uppercase letter (A-Z) excluding O, Q, X.
    Valid first letters: A-N, P, R-W, Y, Z
    Regex character class: [A-NP-RT-WY-Z] ... simplified below.
  - 2nd through 8th characters are decimal digits.
  - Pattern: [A-NP-RT-WY-Z][0-9]{7}

  Correct exclusion set (O, Q, X):
    All letters A-Z minus {O, Q, X}
    = A-N (14 letters), P (skip Q), R-W (skip nothing yet), Y, Z
    Regex: [A-NPR-WYZ] — A to N, P, R to W, Y, Z.
    Note: This intentionally excludes O (15th letter), Q (17th), X (24th).

Confidence tiers:
  HIGH   — Pattern match with explicit header/inline context ("Passport No", "Passport").
  MEDIUM — Bare 8-character pattern match without conflicting context.

False-positive guards:
  - Input is normalised to uppercase before matching (catches mixed-case data).
  - The narrow format (1 letter + 7 digits, specific letter exclusions) keeps FPs low.
  - Context boosting in engine.py upgrades MEDIUM → HIGH on column/label signal.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from enum import Enum


# Correct pattern: first char is any letter EXCEPT O, Q, X.
# [A-NPR-WYZ] = A-N (no O), P (no Q), R-W (no X in range), Y, Z.
# Note: X is the 24th letter (after W=23rd), so R-W correctly excludes X.
_PATTERN = re.compile(r"(?<![A-Z0-9])([A-NPR-WYZ][0-9]{7})(?![A-Z0-9])")


class Confidence(str, Enum):
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"


@dataclass(frozen=True, slots=True)
class PassportMatch:
    raw_value: str
    masked_value: str   # e.g., AXXXX567
    confidence: Confidence
    start: int
    end: int


def _mask(val: str) -> str:
    return f"{val[0]}XXXX{val[-3:]}"


def find_passport(text: str) -> list[PassportMatch]:
    """Return all Indian Passport candidates found in *text*.

    Normalises input to uppercase before scanning so mixed-case data
    (e.g. 'a1234567') is correctly detected.
    """
    upper = text.upper()
    results: list[PassportMatch] = []
    for m in _PATTERN.finditer(upper):
        raw = m.group(1)
        results.append(PassportMatch(
            raw_value=raw,
            masked_value=_mask(raw),
            confidence=Confidence.MEDIUM,
            start=m.start(),
            end=m.end(),
        ))
    return results


# ---------------------------------------------------------------------------
# BaseRecognizer adapter — auto-registers on import
# ---------------------------------------------------------------------------

from .base import BaseRecognizer, RecognizerMatch  # noqa: E402


class PassportRecognizer(BaseRecognizer):
    """Auto-registered BaseRecognizer adapter wrapping find_passport()."""

    entity_type = "PASSPORT"

    def find(self, text: str) -> list[RecognizerMatch]:
        return [
            RecognizerMatch(
                entity_type="PASSPORT",
                raw_value=m.raw_value,
                masked_value=m.masked_value,
                confidence=m.confidence.value,
            )
            for m in find_passport(text)
        ]

