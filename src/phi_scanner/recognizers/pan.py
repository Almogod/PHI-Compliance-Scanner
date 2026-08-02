"""PAN recognizer with structural validation.

PAN format (Income Tax Dept):
  AAAAA9999A  (10 characters)
  [A-Z]{3}  — 3 alphabetic (issuing office / serial)
  [ABCFGHLJPTK] — 4th char: holder-type code
  [A-Z]     — 5th char: first letter of surname / entity name
  [0-9]{4}  — serial digits
  [A-Z]     — alphabetic check character

Holder-type codes (4th character):
  P = Individual, C = Company, H = HUF, F = Firm/LLP, A = AOP,
  T = Trust/AOP-BOI, B = BOI, L = Local Authority,
  J = Artificial Juridical Person, G = Government

Confidence tiers:
  HIGH   — full 10-char pattern matches AND 4th char is a known holder-type.
  MEDIUM — full 10-char pattern matches but 4th char is not in known set
            (could be a new type added after this list; worth review).

No public checksum algorithm is published for PAN. Structural validation
(holder-type code) is the strongest non-network check available.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from enum import Enum

_HOLDER_TYPES: frozenset[str] = frozenset("ABCFGHLJPTK")

# Pattern anchored on word boundaries so "ABCPD1234E" inside a larger token
# is still caught, but partial matches like "ABCPD1234" (9 chars) are not.
_PATTERN = re.compile(r"\b([A-Z]{3})([A-Z])([A-Z])(\d{4})([A-Z])\b")


class Confidence(str, Enum):
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"


@dataclass(frozen=True, slots=True)
class PanMatch:
    raw_value: str
    masked_value: str     # XXXXX1234X
    confidence: Confidence
    holder_type: str | None
    start: int
    end: int


_HOLDER_LABELS: dict[str, str] = {
    "P": "Individual",
    "C": "Company",
    "H": "HUF",
    "F": "Firm/LLP",
    "A": "AOP",
    "T": "Trust",
    "B": "BOI",
    "L": "Local Authority",
    "J": "Artificial Juridical Person",
    "G": "Government",
    "K": "Krish (HUF rep.)",
}


def _mask(value: str) -> str:
    return f"XXXXX{value[5:9]}X"


def find_pan(text: str) -> list[PanMatch]:
    """Return all PAN candidates in *text* with structural validation."""
    # PAN is always uppercase; normalise so mixed-case input is handled.
    upper = text.upper()
    results: list[PanMatch] = []

    for m in _PATTERN.finditer(upper):
        raw = m.group()
        holder_char = m.group(2)  # 4th character of full match
        is_known_type = holder_char in _HOLDER_TYPES
        confidence = Confidence.HIGH if is_known_type else Confidence.MEDIUM
        results.append(PanMatch(
            raw_value=raw,
            masked_value=_mask(raw),
            confidence=confidence,
            holder_type=_HOLDER_LABELS.get(holder_char),
            start=m.start(),
            end=m.end(),
        ))
    return results
