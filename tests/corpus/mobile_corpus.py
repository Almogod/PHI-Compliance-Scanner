"""Synthetic mobile number test corpus.

All numbers are fabricated. The Indian number plan assigns 6xx, 7xx, 8xx, 9xx
series to mobile services. No checksum exists — all matches are MEDIUM confidence.
"""

# ---------------------------------------------------------------------------
# True positives — valid 10-digit numbers starting with 6-9
# ---------------------------------------------------------------------------
TRUE_POSITIVES: list[str] = [
    "9876543210",
    "8765432109",
    "7654321098",
    "6543210987",
    "9123456789",
    "8012345678",
    "7098765432",
    "6789012345",
]

# Various text formats a spreadsheet cell might contain
TRUE_POSITIVE_VARIANTS: list[str] = [
    "+91 9876543210",
    "+91-9876543210",
    "91 9876543210",
    "09876543210",          # 0-prefixed trunk form
    "Mobile: 9876543210",
    "Ph: +919876543210",
    "98765 43210",          # space-separated
]

# ---------------------------------------------------------------------------
# Hard negatives — must NOT be returned as findings
# ---------------------------------------------------------------------------
HARD_NEGATIVES: list[dict] = [
    # Starts with 5 — not assigned to mobile in India
    {"value": "5876543210", "reason": "starts_with_5"},
    # Starts with 1 — landline/special, not mobile
    {"value": "1234567890", "reason": "starts_with_1"},
    # Only 9 digits
    {"value": "987654321", "reason": "too_short_9"},
    # 11 digits starting with 9 — not a mobile number
    {"value": "98765432101", "reason": "too_long_11"},
    # Embedded in a 15-digit string — boundary anchoring should block this
    {"value": "123987654321045", "reason": "embedded_in_longer"},
    # Starts with 0 alone — not valid mobile
    {"value": "0234567890", "reason": "starts_with_0"},
]
