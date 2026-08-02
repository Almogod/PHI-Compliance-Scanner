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

# Voter ID (EPIC): 3 alpha + 7 digits. Masked forms: first 3 alpha visible,
# middle digits replaced with X or *, last 3 digits visible.
_MASKED_VOTER_ID = re.compile(
    r"(?<![A-Z0-9])"
    r"([A-Z]{3}[X*]{4}\d{3})"                    # ABCXXXX567 (first 3 + last 3)
    r"|([A-Z]{3}\d{3}[X*]{4})",                  # ABC567XXXX (first 3 + mid 3)
    re.IGNORECASE,
)

# Passport (Indian): 1 letter + 7 digits. Masked forms: first letter visible,
# middle replaced with X or *, last 3 digits visible.
_MASKED_PASSPORT = re.compile(
    r"(?<![A-Z0-9])"
    r"([A-Z][X*]{4}\d{3})",                      # AXXXX567
    re.IGNORECASE,
)


def detect_masked_identifiers(text: str) -> list[dict[str, str]]:
    """Detect partially-masked identifiers that are still PII exposure risks.

    Returns a list of dicts with 'entity_type' and 'confidence' keys.
    These are reported as separate findings with entity_type suffixed '_MASKED'.

    Covers:
      - AADHAAR_MASKED : XXXX XXXX 1234 / **** **** 1234 forms
      - PAN_MASKED     : XXXXX1234X / *****1234* forms
      - VOTER_ID_MASKED: ABCXXXX567 forms (DPDP Act — partial masking still PII)
      - PASSPORT_MASKED: AXXXX567 forms
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

    # Voter ID masked forms
    for m in _MASKED_VOTER_ID.finditer(upper):
        val = m.group(1) or m.group(2)
        if val and ("X" in val or "*" in val):
            results.append({
                "entity_type": "VOTER_ID_MASKED",
                "masked_value": val,
                "confidence": "LOW",
            })

    # Passport masked forms
    for m in _MASKED_PASSPORT.finditer(upper):
        val = m.group(1)
        if val and ("X" in val or "*" in val):
            results.append({
                "entity_type": "PASSPORT_MASKED",
                "masked_value": val,
                "confidence": "LOW",
            })

    return results


# ---------------------------------------------------------------------------
# Context Weights & Negative Penalties
# ---------------------------------------------------------------------------

CONTEXT_WEIGHTS: dict[str, float] = {
    "aadhaar": 1.0,
    "uid": 0.8,
    "uidad": 0.9,
    "identity": 0.5,
    "card": 0.4,
    "number": 0.2,
    "sl_no": -0.8,
    "invoice": -0.9,
    "ref_no": -0.8,
    "order": -0.8,
    "txn": -0.8,
    "serial": -0.8,
    "item": -0.7,
    "seq": -0.8,
    "row": -0.6,
    "count": -0.7,
    "qty": -0.8,
}

_PENALTY_KEYWORDS = re.compile(
    r"\b(?:sl\s*no|invoice|ref\s*no|order\s*no|txn|serial|seq|qty|item|transaction)\b",
    re.IGNORECASE,
)

# Row context / value-density profiling indicators
_PINCODE_PATTERN = re.compile(r"\b[1-9][0-9]{5}\b")
_MOBILE_PATTERN = re.compile(r"\b[6-9]\d{9}\b")
_EMAIL_PATTERN = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
_PII_NEIGHBOR_KEYWORDS = re.compile(
    r"\b(?:name|address|street|road|nagar|marg|flat|sector|pincode|pin|district|state|city|email|customer|patient|employee|holder)\b",
    re.IGNORECASE,
)


def has_negative_context(column_name: str | None) -> bool:
    """Return True if column_name contains penalty terms like sl_no, invoice, serial, order."""
    if not column_name:
        return False
    norm = column_name.replace("_", " ").replace("-", " ")
    return bool(_PENALTY_KEYWORDS.search(norm))


def detect_row_density(text: str) -> bool:
    """Return True if surrounding text/cells contain supporting PII metadata signals.

    Value-Density Profiling:
      Real PII rarely travels alone. If adjacent cells in a row contain an Indian pincode,
      mobile number, email, or address keywords, confidence is boosted.
    """
    if _PINCODE_PATTERN.search(text):
        return True
    if _MOBILE_PATTERN.search(text):
        return True
    if _EMAIL_PATTERN.search(text):
        return True
    if _PII_NEIGHBOR_KEYWORDS.search(text):
        return True
    return False


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
    column_name: str | None = None,
    has_row_context: bool = False,
) -> str:
    """Upgrade or downgrade confidence tier using context signals & penalties.

    Rules:
      - Column contains penalty terms (invoice, sl_no, ref_no, serial) → Heavy penalty (downgrade to LOW).
      - Column header matches entity type → +1 tier
      - Inline label matches entity type → +1 tier
      - Row-density / neighbor context exists → +1 tier
      - Maximum boost is +1 tier (MEDIUM → HIGH, LOW → MEDIUM)
      - Never exceeds HIGH or drops below LOW
    """
    # 1. Apply heavy penalty if column name indicates non-PII serial/invoice numbers
    if column_name and has_negative_context(column_name):
        return "LOW"

    rank = _CONFIDENCE_ORDER.get(current_confidence, 0)

    # 2. Boost if column header matches, inline label exists, or row density is high
    if column_entity == entity_type or entity_type in inline_labels or has_row_context:
        rank = min(rank + 1, 2)

    return _CONFIDENCE_NAMES[rank]

