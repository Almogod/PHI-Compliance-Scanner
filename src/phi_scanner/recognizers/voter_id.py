"""Voter ID (EPIC) recognizer.

Voter ID / EPIC spec (Election Commission of India):
  - Exactly 10 characters.
  - First 3 characters are uppercase letters (constituency prefix).
  - Last 7 characters are decimal digits.
  - Pattern: [A-Z]{3}[0-9]{7}

Confidence tiers:
  HIGH   — Pattern matches + header/inline context (e.g. "Voter ID", "EPIC").
  MEDIUM — Bare 10-character EPIC pattern match with no conflicting context.
           Emitted cautiously because the pattern is structurally broad.

False-positive guards:
  - Input is normalised to uppercase before matching (catches mixed-case data).
  - Bare matches (no context signals) are always MEDIUM, never HIGH.
  - Context boosting in engine.py upgrades MEDIUM → HIGH when column or label confirms.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from enum import Enum


# Strict word-boundary pattern: 3 uppercase letters then 7 digits.
# Preceded/followed by alphanumeric → rejected (prevents partial matches inside
# longer codes like product SKUs or reference IDs).
_PATTERN = re.compile(r"(?<![A-Z0-9])([A-Z]{3}[0-9]{7})(?![A-Z0-9])")


class Confidence(str, Enum):
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"


@dataclass(frozen=True, slots=True)
class VoterIdMatch:
    raw_value: str
    masked_value: str   # e.g., ABCXXXX567
    confidence: Confidence
    start: int
    end: int


def _mask(val: str) -> str:
    return f"{val[:3]}XXXX{val[-3:]}"


def find_voter_id(text: str) -> list[VoterIdMatch]:
    """Return all Voter ID (EPIC) candidates found in *text*.

    Normalises input to uppercase before scanning so mixed-case data
    (e.g. 'abc1234567') is correctly detected.
    """
    upper = text.upper()
    results: list[VoterIdMatch] = []
    for m in _PATTERN.finditer(upper):
        raw = m.group(1)
        results.append(VoterIdMatch(
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


class VoterIdRecognizer(BaseRecognizer):
    """Auto-registered BaseRecognizer adapter wrapping find_voter_id()."""

    entity_type = "VOTER_ID"

    def find(self, text: str) -> list[RecognizerMatch]:
        return [
            RecognizerMatch(
                entity_type="VOTER_ID",
                raw_value=m.raw_value,
                masked_value=m.masked_value,
                confidence=m.confidence.value,
            )
            for m in find_voter_id(text)
        ]
