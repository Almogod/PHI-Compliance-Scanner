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

v2 improvements:
  - Handles spaces within PAN ("ABC PD 1234 E" → "ABCPD1234E")
  - Guards against email false positives (ABCPD1234E@gmail.com)
  - Guards against URL/path false positives
  - Handles mixed case (lowercase PAN in messy data)
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from enum import Enum

_HOLDER_TYPES: frozenset[str] = frozenset("ABCFGHLJPTK")

# Primary pattern — standard word-boundary anchored PAN
_PATTERN = re.compile(r"\b([A-Z]{3})([A-Z])([A-Z])(\d{4})([A-Z])\b")

# Secondary pattern — PAN with spaces between groups (seen in real data)
# E.g., "ABC PD 1234 E" or "ABCPD 1234E"
_PATTERN_SPACED = re.compile(
    r"\b([A-Z]{3})\s*([A-Z])\s*([A-Z])\s*(\d{4})\s*([A-Z])\b"
)

# Email pattern — PAN followed by @ is almost certainly part of an email
_EMAIL_SUFFIX = re.compile(r"@")

# URL/path patterns — only actual path separators, NOT colons
# (colons appear in labels like "PAN: ABCPD1234E" and would cause false negatives)
_PATH_CONTEXT = re.compile(r"[/\\]")


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


def _is_email_context(text: str, match_end: int) -> bool:
    """Return True if the PAN match is immediately followed by '@'."""
    remaining = text[match_end:match_end + 1]
    return remaining == "@"


def _is_path_context(text: str, match_start: int) -> bool:
    """Return True if the PAN match is preceded by path-like characters."""
    if match_start == 0:
        return False
    preceding = text[max(0, match_start - 3):match_start]
    return bool(_PATH_CONTEXT.search(preceding))


def find_pan(text: str) -> list[PanMatch]:
    """Return all PAN candidates in *text* with structural validation.

    Improvements over v1:
    - Handles mixed case (normalises to uppercase)
    - Checks for email context (PAN@domain = not a PAN)
    - Checks for path context (/ABCPD1234E = likely a path, not PAN)
    - Runs a secondary pass for spaced PANs ("ABC PD 1234 E")
    """
    upper = text.upper()
    results: list[PanMatch] = []
    seen_values: set[str] = set()  # deduplicate across primary + spaced passes

    for pattern in [_PATTERN, _PATTERN_SPACED]:
        for m in pattern.finditer(upper):
            raw = m.group(1) + m.group(2) + m.group(3) + m.group(4) + m.group(5)

            # Dedup: same PAN found by both patterns
            if raw in seen_values:
                continue
            seen_values.add(raw)

            # False-positive guards
            if _is_email_context(upper, m.end()):
                continue
            if _is_path_context(upper, m.start()):
                continue

            holder_char = m.group(2)  # 4th character of PAN
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
