"""Synthetic Aadhaar test corpus — true positives and hard negatives.

All numbers here are fabricated for testing. None are real Aadhaar numbers.
The corpus satisfies rules.md §11: true positives + hard negatives committed
alongside the recognizer.

Generating valid numbers:
  prefix (11 digits, first digit 2-9) + verhoeff_check_digit(prefix)

Hard negatives intentionally chosen:
  - 12 digits starting with 0 or 1 (valid length, invalid first digit)
  - 12 digits starting with 2-9 but failing Verhoeff (off-by-one in last digit)
  - 11 digits (too short)
  - 13 digits (too long)
  - Numbers that look like Aadhaar embedded in longer numeric strings
"""
from phi_scanner.recognizers.aadhaar import verhoeff_check_digit


def _make(prefix: str) -> str:
    return prefix + verhoeff_check_digit(prefix)


# ---------------------------------------------------------------------------
# True positives — valid Aadhaar numbers (checksum passes, first digit 2-9)
# ---------------------------------------------------------------------------
TRUE_POSITIVES: list[str] = [
    _make("23456789012"),
    _make("34567890123"),
    _make("45678901234"),
    _make("56789012345"),
    _make("67890123456"),
    _make("78901234567"),
    _make("89012345678"),
    _make("90123456789"),
    _make("29876543210"),
    _make("31122334455"),
]

# Plain-text forms as they might appear in a spreadsheet cell
TRUE_POSITIVE_VARIANTS: list[str] = [
    f"{TRUE_POSITIVES[0][:4]} {TRUE_POSITIVES[0][4:8]} {TRUE_POSITIVES[0][8:]}",  # spaced
    f"{TRUE_POSITIVES[1][:4]}-{TRUE_POSITIVES[1][4:8]}-{TRUE_POSITIVES[1][8:]}",  # hyphenated
    f"Aadhaar: {TRUE_POSITIVES[2]}",
    f"UID={TRUE_POSITIVES[3]}",
]

# ---------------------------------------------------------------------------
# Hard negatives — must NOT be returned as HIGH confidence findings
# ---------------------------------------------------------------------------
HARD_NEGATIVES: list[dict] = [
    # Fails Verhoeff (last digit incremented by 1, wrapping 9→0)
    {
        "value": _make("23456789012")[:-1] + str((int(_make("23456789012")[-1]) + 1) % 10),
        "reason": "verhoeff_fail",
    },
    # First digit 0 — not assigned by UIDAI
    {"value": "012345678901", "reason": "first_digit_0"},
    # First digit 1 — not assigned by UIDAI
    {"value": "112345678901", "reason": "first_digit_1"},
    # 11 digits — too short
    {"value": "23456789012", "reason": "too_short_11"},
    # 13 digits — too long
    {"value": "2345678901234", "reason": "too_long_13"},
    # 12 digits embedded in a 15-digit numeric string — boundary check
    {"value": f"123{_make('23456789012')}456", "reason": "embedded_in_longer"},
    # All zeros — structurally invalid
    {"value": "000000000000", "reason": "all_zeros"},
]
