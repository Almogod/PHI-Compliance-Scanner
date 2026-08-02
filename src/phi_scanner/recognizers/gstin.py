"""GSTIN recognizer with checksum validation.

GSTIN structure (15 characters):
  [0-9]{2}   — State/UT code (01–38; see _VALID_STATE_CODES)
  [A-Z]{3}   — PAN chars 1–3 (alpha)
  [ABCFGHLJPTK] — PAN char 4: holder-type
  [A-Z]      — PAN char 5: surname initial
  [0-9]{4}   — PAN serial
  [A-Z]      — PAN alpha check char
  [1-9A-Z]   — Entity number within the PAN (default '1')
  Z          — Always 'Z' (reserved by GST Council)
  [0-9A-Z]   — Check digit (computed, see _gstin_check_digit)

Checksum algorithm (public, used by GST portal):
  Weighted modular sum over 14 characters using the 36-char alphabet
  "0-9A-Z", alternating weight factors 1 and 2, reducing products >= 36
  via floor-div + mod, then (36 - sum%36) % 36.

Confidence tiers:
  HIGH   — full pattern match + valid state code + checksum passes.
  MEDIUM — pattern match + valid state code, checksum fails (data entry error
            or schema variant worth reviewing).
  LOW    — pattern shape matches but state code is unrecognised.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from enum import Enum

_CHARS = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ"
_CHAR_VALUE: dict[str, int] = {c: i for i, c in enumerate(_CHARS)}

# Valid state/UT codes as of GST rollout (01–38, some gaps).
_VALID_STATE_CODES: frozenset[str] = frozenset(
    f"{n:02d}" for n in [
        1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19,
        20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36,
        37, 38,
    ]
)

# Holder-type codes (same as PAN 4th char)
_HOLDER_TYPES: frozenset[str] = frozenset("ABCFGHLJPTK")

_PATTERN = re.compile(
    r"\b(\d{2})"                    # state code
    r"([A-Z]{3})"                   # PAN 1-3
    r"([A-Z])"                      # PAN 4 (holder type)
    r"([A-Z])"                      # PAN 5
    r"(\d{4})"                      # PAN serial
    r"([A-Z])"                      # PAN check char
    r"([1-9A-Z])"                   # entity number
    r"(Z)"                          # always Z
    r"([0-9A-Z])\b"                 # check digit
)


class Confidence(str, Enum):
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"


@dataclass(frozen=True, slots=True)
class GstinMatch:
    raw_value: str
    masked_value: str       # state + XXXXXXXXXX + last 3
    confidence: Confidence
    state_code: str
    start: int
    end: int


def _gstin_check_digit(prefix14: str) -> str:
    """Compute check digit for a 14-character GSTIN prefix."""
    factor = 1
    total = 0
    for ch in prefix14:
        product = factor * _CHAR_VALUE[ch]
        factor = 2 if factor == 1 else 1
        product = (product // 36) + (product % 36)
        total += product
    remainder = total % 36
    return _CHARS[(36 - remainder) % 36]


def validate_gstin(gstin: str) -> bool:
    """Return True if the 15-character GSTIN passes its checksum."""
    if len(gstin) != 15:
        return False
    try:
        return _gstin_check_digit(gstin[:14]) == gstin[14]
    except KeyError:
        return False


def _mask(value: str) -> str:
    return f"{value[:2]}XXXXXXXXXX{value[12:]}"


def find_gstin(text: str) -> list[GstinMatch]:
    """Return all GSTIN candidates in *text* with state-code + checksum validation."""
    upper = text.upper()
    results: list[GstinMatch] = []

    for m in _PATTERN.finditer(upper):
        raw = m.group()
        state_code = m.group(1)
        valid_state = state_code in _VALID_STATE_CODES
        checksum_ok = validate_gstin(raw)

        if valid_state and checksum_ok:
            confidence = Confidence.HIGH
        elif valid_state:
            confidence = Confidence.MEDIUM
        else:
            confidence = Confidence.LOW

        results.append(GstinMatch(
            raw_value=raw,
            masked_value=_mask(raw),
            confidence=confidence,
            state_code=state_code,
            start=m.start(),
            end=m.end(),
        ))
    return results


# ---------------------------------------------------------------------------
# BaseRecognizer adapter — auto-registers on import
# ---------------------------------------------------------------------------

from .base import BaseRecognizer, RecognizerMatch  # noqa: E402


class GstinRecognizer(BaseRecognizer):
    """Auto-registered BaseRecognizer adapter wrapping find_gstin()."""

    entity_type = "GSTIN"

    def find(self, text: str) -> list[RecognizerMatch]:
        return [
            RecognizerMatch(
                entity_type="GSTIN",
                raw_value=m.raw_value,
                masked_value=m.masked_value,
                confidence=m.confidence.value,
                extra={"state_code": m.state_code},
            )
            for m in find_gstin(text)
        ]
