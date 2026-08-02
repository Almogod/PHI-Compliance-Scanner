"""Context signals — column headers, labels, and sheet names that boost confidence.

In a compliance scanner, false negatives are more dangerous than false positives.
When a column is named "aadhaar_number" and a cell in it contains a 12-digit
number that fails Verhoeff, that is almost certainly a transcription error —
not a false alarm. Context-aware confidence boosting handles this.

This module provides:
  1. Column-header → entity-type mapping (which column headers imply which PII)
  2. Inline label detection ("PAN: ABCPD1234E" → the "PAN:" prefix is a signal)
  3. Confidence boosting rules (context can upgrade MEDIUM → HIGH or LOW → MEDIUM,
     but never introduces a finding from nothing)

Design note: context only *boosts* confidence — never *creates* findings.
A string "hello world" in an "aadhaar" column does not become a finding.
"""
from __future__ import annotations

import re


# ---------------------------------------------------------------------------
# Column header → entity type mapping
# ---------------------------------------------------------------------------

# Patterns that indicate a column likely contains a specific identifier.
# Matched case-insensitively against the column header / sheet name.
# Multiple synonyms per identifier to catch Indian business naming conventions.

_HEADER_PATTERNS: dict[str, list[re.Pattern[str]]] = {
    "AADHAAR": [
        re.compile(r"\b(?:aadhaar|aadhar|adhar|aadhr|uid)\b", re.IGNORECASE),
        re.compile(r"\b(?:unique\s*id(?:entification)?)\b", re.IGNORECASE),
    ],
    "PAN": [
        re.compile(r"\bpan\b", re.IGNORECASE),
        re.compile(r"\b(?:permanent\s*account\s*(?:no|num|number)?)\b", re.IGNORECASE),
        re.compile(r"\bincome\s*tax\s*(?:no|num|number|id)?\b", re.IGNORECASE),
    ],
    "GSTIN": [
        re.compile(r"\b(?:gstin?|gst\s*(?:no|num|number|id)?)\b", re.IGNORECASE),
        re.compile(r"\b(?:goods\s*(?:and|&)\s*services?\s*tax)\b", re.IGNORECASE),
    ],
    "IN_MOBILE": [
        re.compile(r"\b(?:mobile|mob|phone|ph|tel|cell|contact)\s*(?:no|num|number)?\b", re.IGNORECASE),
        re.compile(r"\b(?:whatsapp|wa)\s*(?:no|num|number)?\b", re.IGNORECASE),
    ],
    "VOTER_ID": [
        re.compile(r"\b(?:voter\s*id|epic|voter\s*no|elector\s*photo)\b", re.IGNORECASE),
    ],
    "PASSPORT": [
        re.compile(r"\b(?:passport\s*no|passport\s*num|passport\s*number|ppt\s*no)\b", re.IGNORECASE),
    ],
}


def detect_column_entity(column_name: str) -> str | None:
    """Return the entity type implied by a column header, or None.

    Normalises underscores and common separators to spaces before matching,
    so column names like 'aadhaar_no' and 'gst-number' are handled.

    Examples:
      "Aadhaar No."  → "AADHAAR"
      "GST Number"   → "GSTIN"
      "aadhaar_no"   → "AADHAAR"
      "employee_id"  → None
    """
    # Normalise separators to spaces so \b works with underscore-delimited names
    normalised = column_name.replace("_", " ").replace("-", " ").replace(".", " ")
    for entity_type, patterns in _HEADER_PATTERNS.items():
        for pattern in patterns:
            if pattern.search(normalised):
                return entity_type
    return None


# ---------------------------------------------------------------------------
# Inline label detection
# ---------------------------------------------------------------------------

# Labels that commonly prefix an identifier value within a cell.
# E.g., "PAN: ABCPD1234E" or "Aadhaar No - 2345 6789 0124"
_INLINE_LABELS: dict[str, re.Pattern[str]] = {
    "AADHAAR": re.compile(
        r"(?:aadhaar|aadhar|adhar|uid|unique\s*id)"
        r"[\s]*(?:no\.?|num(?:ber)?|#|:|\-|=)?[\s:=\-]*",
        re.IGNORECASE,
    ),
    "PAN": re.compile(
        r"(?:pan|permanent\s*account)"
        r"[\s]*(?:no\.?|num(?:ber)?|#|:|\-|=)?[\s:=\-]*",
        re.IGNORECASE,
    ),
    "GSTIN": re.compile(
        r"(?:gstin?|gst)"
        r"[\s]*(?:no\.?|num(?:ber)?|#|:|\-|=)?[\s:=\-]*",
        re.IGNORECASE,
    ),
    "IN_MOBILE": re.compile(
        r"(?:mob(?:ile)?|phone|ph|tel|contact|cell|whatsapp|wa)"
        r"[\s]*(?:no\.?|num(?:ber)?|#|:|\-|=)?[\s:=\-]*",
        re.IGNORECASE,
    ),
}


def detect_inline_labels(text: str) -> set[str]:
    """Return the set of entity types whose labels appear in *text*.

    Examples:
      "PAN: ABCPD1234E, GSTIN: 27AAPFU0939F1ZV"  → {"PAN", "GSTIN"}
      "9876543210"  → set()
    """
    found: set[str] = set()
    for entity_type, pattern in _INLINE_LABELS.items():
        if pattern.search(text):
            found.add(entity_type)
    return found


# ---------------------------------------------------------------------------
# Partially-masked identifier detection
# ---------------------------------------------------------------------------

# People sometimes store partially-masked identifiers thinking they're safe.
# "XXXX XXXX 1234" is still PII — the last 4 digits + column header can
# re-identify someone. We flag these with a special entity type.

_MASKED_AADHAAR = re.compile(
    r"(?:X{4}[\s\-]*X{4}[\s\-]*\d{4})"         # XXXX XXXX 1234
    r"|(?:\*{4}[\s\-]*\*{4}[\s\-]*\d{4})"       # **** **** 1234
    r"|(?:X{8}[\s\-]*\d{4})"                     # XXXXXXXX 1234
    r"|(?:\d{4}[\s\-]*X{4}[\s\-]*X{4})",         # 1234 XXXX XXXX (reverse mask)
    re.IGNORECASE,
)

_MASKED_PAN = re.compile(
    r"(?:[A-Z*X]{5}\d{4}[A-Z*X])"               # XXXXX1234X or *****1234*
    r"|(?:[A-Z]{3}[A-Z*X]{2}\d{4}[A-Z])",       # ABCXX1234E (partial mask)
    re.IGNORECASE,
)


def detect_masked_identifiers(text: str) -> list[dict[str, str]]:
    """Detect partially-masked identifiers that are still PII exposure risks.

    Returns a list of dicts with 'entity_type' and 'confidence' keys.
    These are reported as separate findings with entity_type suffixed '_MASKED'.
    """
    results: list[dict[str, str]] = []

    for m in _MASKED_AADHAAR.finditer(text):
        results.append({
            "entity_type": "AADHAAR_MASKED",
            "masked_value": m.group(),
            "confidence": "MEDIUM",
        })

    # Only flag masked PAN if it has actual mask characters (* or X mixed with alpha)
    upper = text.upper()
    for m in _MASKED_PAN.finditer(upper):
        val = m.group()
        # Must contain at least one mask character to be flagged
        if "*" in val or ("X" in val and not val.isalpha()):
            results.append({
                "entity_type": "PAN_MASKED",
                "masked_value": val,
                "confidence": "LOW",
            })

    return results


# ---------------------------------------------------------------------------
# Confidence boosting
# ---------------------------------------------------------------------------

_CONFIDENCE_ORDER = {"LOW": 0, "MEDIUM": 1, "HIGH": 2}
_CONFIDENCE_NAMES = {0: "LOW", 1: "MEDIUM", 2: "HIGH"}


def boost_confidence(
    current_confidence: str,
    entity_type: str,
    column_entity: str | None,
    inline_labels: set[str],
) -> str:
    """Upgrade confidence by one tier if context signals match the entity type.

    Rules:
      - Column header matches entity type → +1 tier
      - Inline label matches entity type → +1 tier (not cumulative with column)
      - Maximum boost is +1 tier (MEDIUM → HIGH, LOW → MEDIUM)
      - Never exceeds HIGH

    This means a MEDIUM-confidence Aadhaar in an "aadhaar" column → HIGH.
    A MEDIUM mobile number stays MEDIUM unless the column says "phone".
    """
    rank = _CONFIDENCE_ORDER.get(current_confidence, 0)

    if column_entity == entity_type or entity_type in inline_labels:
        rank = min(rank + 1, 2)

    return _CONFIDENCE_NAMES[rank]
