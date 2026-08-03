"""Context signals — column headers, labels, and sheet names that boost confidence.

Supports multi-lingual Indian contexts (Hindi, Devanagari, Bengali, Tamil, Telugu).
"""
from __future__ import annotations

import re


# ---------------------------------------------------------------------------
# Column header → entity type mapping (Multi-Lingual)
# ---------------------------------------------------------------------------

_HEADER_PATTERNS: dict[str, list[re.Pattern[str]]] = {
    "AADHAAR": [
        re.compile(r"\b(?:aadhaar|aadhar|adhar|aadhr|uid)\b", re.IGNORECASE),
        re.compile(r"\b(?:unique\s*id(?:entification)?)\b", re.IGNORECASE),
        re.compile(r"(?:आधार|ইউআইডি|ஆதார்|ఆధార్)"),
    ],
    "PAN": [
        re.compile(r"\bpan\b", re.IGNORECASE),
        re.compile(r"\b(?:permanent\s*account\s*(?:no|num|number)?)\b", re.IGNORECASE),
        re.compile(r"\bincome\s*tax\s*(?:no|num|number|id)?\b", re.IGNORECASE),
        re.compile(r"(?:पैन|पैन\s*संख्या|প্যান|பான்)"),
    ],
    "GSTIN": [
        re.compile(r"\b(?:gstin?|gst\s*(?:no|num|number|id)?)\b", re.IGNORECASE),
        re.compile(r"\b(?:goods\s*(?:and|&)\s*services?\s*tax)\b", re.IGNORECASE),
        re.compile(r"(?:जीएसटी|जीएसटीin)"),
    ],
    "IN_MOBILE": [
        re.compile(r"\b(?:mobile|mob|phone|ph|tel|cell|contact)\s*(?:no|num|number)?\b", re.IGNORECASE),
        re.compile(r"\b(?:whatsapp|wa)\s*(?:no|num|number)?\b", re.IGNORECASE),
        re.compile(r"(?:मोबाइल|फोन|संपर्क|মোবাইল|போன்)"),
    ],
    "VOTER_ID": [
        re.compile(r"\b(?:voter\s*id|epic|voter\s*no|elector\s*photo)\b", re.IGNORECASE),
        re.compile(r"(?:मतदाता|पहचान\s*पत्र)"),
    ],
    "PASSPORT": [
        re.compile(r"\b(?:passport\s*no|passport\s*num|passport\s*number|ppt\s*no)\b", re.IGNORECASE),
        re.compile(r"(?:पासपोर्ट)"),
    ],
    "BANK_ACCOUNT": [
        re.compile(r"\b(?:account|acct|acc)\s*(?:no|num|number)?\b", re.IGNORECASE),
        re.compile(r"(?:खाता|खाता\s*सं|खाता\s*संख्या)"),
    ],
    "IFSC": [
        re.compile(r"\b(?:ifsc|ifsc\s*code)\b", re.IGNORECASE),
        re.compile(r"(?:आईएफएससी)"),
    ],
}


def detect_column_entity(column_name: str) -> str | None:
    """Return the entity type implied by a column header, or None."""
    normalised = column_name.replace("_", " ").replace("-", " ").replace(".", " ")
    for entity_type, patterns in _HEADER_PATTERNS.items():
        for pattern in patterns:
            if pattern.search(normalised):
                return entity_type
    return None


# ---------------------------------------------------------------------------
# Inline label detection (Multi-Lingual)
# ---------------------------------------------------------------------------

_INLINE_LABELS: dict[str, re.Pattern[str]] = {
    "AADHAAR": re.compile(
        r"(?:aadhaar|aadhar|adhar|uid|unique\s*id|आधार|ஆதார்|ஆதார்\s*எண்|ইউআইডি)"
        r"[\s]*(?:no\.?|num(?:ber)?|#|:|\-|=)?[\s:=\-]*",
        re.IGNORECASE,
    ),
    "PAN": re.compile(
        r"(?:pan|permanent\s*account|पैन|पैन\s*सं|பான்|প্যান)"
        r"[\s]*(?:no\.?|num(?:ber)?|#|:|\-|=)?[\s:=\-]*",
        re.IGNORECASE,
    ),
    "GSTIN": re.compile(
        r"(?:gstin?|gst|जीएसटी)"
        r"[\s]*(?:no\.?|num(?:ber)?|#|:|\-|=)?[\s:=\-]*",
        re.IGNORECASE,
    ),
    "IN_MOBILE": re.compile(
        r"(?:mob(?:ile)?|phone|ph|tel|contact|cell|whatsapp|wa|मोबाइल|फोन|संपर्क|போன்)"
        r"[\s]*(?:no\.?|num(?:ber)?|#|:|\-|=)?[\s:=\-]*",
        re.IGNORECASE,
    ),
    "BANK_ACCOUNT": re.compile(
        r"(?:account|acct|acc|खाता)"
        r"[\s]*(?:no\.?|num(?:ber)?|#|:|\-|=)?[\s:=\-]*",
        re.IGNORECASE,
    ),
    "IFSC": re.compile(
        r"(?:ifsc|आईएफएससी)"
        r"[\s]*(?:code|no\.?|#|:|\-|=)?[\s:=\-]*",
        re.IGNORECASE,
    ),
}


def detect_inline_labels(text: str) -> set[str]:
    """Return the set of entity types whose labels appear in *text*."""
    found: set[str] = set()
    for entity_type, pattern in _INLINE_LABELS.items():
        if pattern.search(text):
            found.add(entity_type)
    return found


# ---------------------------------------------------------------------------
# Partially-masked identifier detection
# ---------------------------------------------------------------------------

_MASKED_AADHAAR = re.compile(
    r"(?:X{4}[\s\-]*X{4}[\s\-]*\d{4})"
    r"|(?:\*{4}[\s\-]*\*{4}[\s\-]*\d{4})"
    r"|(?:X{8}[\s\-]*\d{4})"
    r"|(?:\d{4}[\s\-]*X{4}[\s\-]*X{4})",
    re.IGNORECASE,
)

_MASKED_PAN = re.compile(
    r"(?:[A-Z*X]{5}\d{4}[A-Z*X])"
    r"|(?:[A-Z]{3}[A-Z*X]{2}\d{4}[A-Z])",
    re.IGNORECASE,
)

_MASKED_VOTER_ID = re.compile(
    r"(?<![A-Z0-9])"
    r"([A-Z]{3}[X*]{4}\d{3})"
    r"|([A-Z]{3}\d{3}[X*]{4})",
    re.IGNORECASE,
)

_MASKED_PASSPORT = re.compile(
    r"(?<![A-Z0-9])"
    r"([A-Z][X*]{4}\d{3})",
    re.IGNORECASE,
)


def detect_masked_identifiers(text: str) -> list[dict[str, str]]:
    """Detect partially-masked identifiers."""
    results: list[dict[str, str]] = []

    for m in _MASKED_AADHAAR.finditer(text):
        results.append({
            "entity_type": "AADHAAR_MASKED",
            "masked_value": m.group(),
            "confidence": "MEDIUM",
        })

    upper = text.upper()
    for m in _MASKED_PAN.finditer(upper):
        val = m.group()
        if "*" in val or ("X" in val and not val.isalpha()):
            results.append({
                "entity_type": "PAN_MASKED",
                "masked_value": val,
                "confidence": "LOW",
            })

    for m in _MASKED_VOTER_ID.finditer(upper):
        val = m.group(1) or m.group(2)
        if val and ("X" in val or "*" in val):
            results.append({
                "entity_type": "VOTER_ID_MASKED",
                "masked_value": val,
                "confidence": "LOW",
            })

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
# Context Weights & Penalties
# ---------------------------------------------------------------------------

_PENALTY_KEYWORDS = re.compile(
    r"\b(?:sl\s*no|invoice|ref\s*no|order\s*no|txn|serial|seq|qty|item|transaction)\b",
    re.IGNORECASE,
)

_PINCODE_PATTERN = re.compile(r"\b[1-9][0-9]{5}\b")
_MOBILE_PATTERN = re.compile(r"\b[6-9]\d{9}\b")
_EMAIL_PATTERN = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
_PII_NEIGHBOR_KEYWORDS = re.compile(
    r"\b(?:name|address|street|road|nagar|marg|flat|sector|pincode|pin|district|state|city|email|customer|patient|employee|holder|नाम|पता|शहर|पिनकोड)\b",
    re.IGNORECASE,
)


def has_negative_context(column_name: str | None) -> bool:
    if not column_name:
        return False
    norm = column_name.replace("_", " ").replace("-", " ")
    return bool(_PENALTY_KEYWORDS.search(norm))


def detect_row_density(text: str) -> bool:
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
    if column_name and has_negative_context(column_name):
        return "LOW"

    rank = _CONFIDENCE_ORDER.get(current_confidence, 0)
    if column_entity == entity_type or entity_type in inline_labels or has_row_context:
        rank = min(rank + 1, 2)

    return _CONFIDENCE_NAMES[rank]
