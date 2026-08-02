"""Synthetic PAN test corpus.

PAN format: [A-Z]{3}[ABCFGHLJPTK][A-Z][0-9]{4}[A-Z]

True positives cover each holder-type code.
Hard negatives cover invalid holder-type codes, wrong length, wrong structure.
"""

# ---------------------------------------------------------------------------
# True positives — structurally valid PANs with known holder-type codes
# ---------------------------------------------------------------------------
TRUE_POSITIVES: list[dict] = [
    {"value": "ABCPD1234E", "holder_type": "Individual"},
    {"value": "XYZCA5678F", "holder_type": "Company"},
    {"value": "DEFHG2345K", "holder_type": "HUF"},
    {"value": "MNOFS6789L", "holder_type": "Firm/LLP"},
    {"value": "PQRAT1111M", "holder_type": "AOP"},
    {"value": "RSTTN2222N", "holder_type": "Trust"},
    {"value": "UVWBZ3333P", "holder_type": "BOI"},
    {"value": "GHILR4444Q", "holder_type": "Local Authority"},
    {"value": "JKLJX5555R", "holder_type": "AJP"},
    {"value": "ABCGK6789S", "holder_type": "Government"},
    {"value": "ABCPD1234E", "holder_type": "Individual"},  # duplicate to test dedup
]

# As they might appear in a cell
TRUE_POSITIVE_VARIANTS: list[str] = [
    "PAN: ABCPD1234E",
    "pan no. xyzca5678f",   # lowercase — should still be caught after upper()
    "ABCPD1234E / GSTIN attached",
]

# ---------------------------------------------------------------------------
# Hard negatives — must NOT fire as HIGH confidence
# ---------------------------------------------------------------------------
HARD_NEGATIVES: list[dict] = [
    # Invalid holder-type code (4th char 'D' not in set)
    {"value": "ABCDD1234E", "reason": "invalid_holder_type"},
    # Only 9 characters
    {"value": "ABCPD123E", "reason": "too_short_9"},
    # 11 characters
    {"value": "ABCPD12345E", "reason": "too_long_11"},
    # Digits where alpha expected (first 3 chars)
    {"value": "123PD1234E", "reason": "digits_in_alpha_prefix"},
    # All same letter — unlikely real but structurally matches shape
    # 4th char 'E' not in valid set → should be MEDIUM not HIGH
    {"value": "AAAED9999A", "reason": "invalid_holder_type_E"},
    # Too short: 8 chars
    {"value": "ABCP1234", "reason": "too_short_8"},
]
