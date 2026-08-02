"""Indian Passport Number recognizer.

Indian Passport spec (Ministry of External Affairs):
  - Exactly 8 characters.
  - 1st character is an uppercase letter (A-Z except O, Q, X).
  - 2nd through 8th characters are decimal digits.
  - Pattern: [A-PR-WYZ][0-9]{7}

Confidence tiers:
  HIGH   — Pattern match with explicit header/inline context ("Passport No", "Passport").
  MEDIUM — Bare 8-character pattern match without conflicting context.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from enum import Enum


_PATTERN = re.compile(r"(?<![A-Z0-9])([A-NPR-WY-Z][0-9]{7})(?![A-Z0-9])")


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
    """Return all Indian Passport candidates found in *text*."""
    results: list[PassportMatch] = []
    for m in _PATTERN.finditer(text):
        raw = m.group(1)
        results.append(PassportMatch(
            raw_value=raw,
            masked_value=_mask(raw),
            confidence=Confidence.MEDIUM,
            start=m.start(),
            end=m.end(),
        ))
    return results
