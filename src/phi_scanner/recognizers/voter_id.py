"""Voter ID (EPIC) recognizer.

Voter ID / EPIC spec (Election Commission of India):
  - Exactly 10 characters.
  - First 3 characters are uppercase letters (constituency prefix).
  - Last 7 characters are decimal digits.
  - Pattern: [A-Z]{3}[0-9]{7}

Confidence tiers:
  HIGH   — Pattern matches + header/inline context (e.g. "Voter ID", "EPIC").
  MEDIUM — Bare 10-character EPIC pattern match without conflicting context.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from enum import Enum


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
    """Return all Voter ID (EPIC) candidates found in *text*."""
    results: list[VoterIdMatch] = []
    for m in _PATTERN.finditer(text):
        raw = m.group(1)
        results.append(VoterIdMatch(
            raw_value=raw,
            masked_value=_mask(raw),
            confidence=Confidence.MEDIUM,
            start=m.start(),
            end=m.end(),
        ))
    return results
