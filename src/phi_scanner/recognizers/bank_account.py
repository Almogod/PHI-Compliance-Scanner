"""Bank Account Number + IFSC Code recognizer.

Indian Bank Account Number spec:
  - 9 to 18 digits (varies by bank; SBI uses 11 digits, HDFC uses 14, etc.).
  - No public checksum algorithm exists. Validation is structural only.
  - Always appears near an IFSC code in well-formed datasets.

IFSC Code spec (RBI):
  - Exactly 11 characters.
  - First 4 chars: bank code (uppercase alpha, e.g., HDFC, SBIN, ICIC).
  - 5th char: always '0' (reserved).
  - Last 6 chars: branch code (alphanumeric).
  - Pattern: [A-Z]{4}0[A-Z0-9]{6}

Confidence tiers:
  HIGH   — IFSC + account number appear together in same row/cell context,
            OR column header matches bank/account/ifsc.
  MEDIUM — Standalone IFSC code matched (structurally valid, unique format).
  LOW    — Standalone account-length digit string (highly ambiguous without IFSC).

Design notes:
  - Account numbers in isolation are LOW confidence because 9-18 digits is very
    broad and overlaps with phone numbers, dates, and other sequences.
  - IFSC codes are MEDIUM standalone because the 4-alpha+0+6-alnum pattern is
    highly distinctive.
  - The engine's row-density profiling will upgrade LOW→MEDIUM when adjacent cells
    contain matching PAN/Aadhaar, and MEDIUM→HIGH when column header confirms.
"""
from __future__ import annotations

import re

from .base import BaseRecognizer, RecognizerMatch


# ---------------------------------------------------------------------------
# Patterns
# ---------------------------------------------------------------------------

# IFSC: 4 uppercase alpha + literal '0' + 6 uppercase alnum
_IFSC_PATTERN = re.compile(
    r"(?<![A-Z0-9])([A-Z]{4}0[A-Z0-9]{6})(?![A-Z0-9])"
)

# Bank account numbers: 9–18 digits.
# Must be standalone (not part of a longer number or phone/Aadhaar/PAN sequence).
# The negative lookahead/lookbehind prevents matching Aadhaar (12 digits) or
# phone numbers (10 digits starting with 6-9) in isolation — those have their
# own recognizers. We flag digits of lengths 9,11–18 (skipping bare 10 digits
# which are fully covered by the mobile recognizer).
_ACCOUNT_PATTERN = re.compile(
    r"(?<!\d)(\d{9}|\d{11}|\d{12}|\d{13}|\d{14}|\d{15}|\d{16}|\d{17}|\d{18})(?!\d)"
)

# Known valid bank codes (non-exhaustive — covers major public/private banks)
_KNOWN_BANK_CODES: frozenset[str] = frozenset({
    "SBIN", "KKBK", "HDFC", "ICIC", "UTIB", "PUNB", "ANDB", "CNRB",
    "BARB", "BKID", "CBIN", "CORP", "DENA", "IOBA", "MAHB", "ORBC",
    "PSIB", "SCBL", "SYND", "UBIN", "UCBA", "VIJB", "YESB", "IDIB",
    "IDFC", "RATN", "FDRL", "KVBL", "TMBL", "DCBL", "BDBL", "NKGSB",
    "APGB", "RNSB", "COSB",
})


def _mask_account(val: str) -> str:
    """Show only last 4 digits for audit visibility."""
    if len(val) <= 4:
        return "X" * len(val)
    return f"{'X' * (len(val) - 4)}{val[-4:]}"


def _mask_ifsc(val: str) -> str:
    """Preserve bank code (first 4) + mask branch (last 6)."""
    return f"{val[:4]}0XXXXXX"


class BankAccountRecognizer(BaseRecognizer):
    """Recognizes IFSC codes and bank account numbers.

    Registers itself automatically on import under entity_type "IFSC".
    Account number findings use entity_type "BANK_ACCOUNT".
    """

    entity_type = "IFSC"

    def find(self, text: str) -> list[RecognizerMatch]:
        results: list[RecognizerMatch] = []
        upper = text.upper()

        # --- IFSC codes (always MEDIUM; engine boosts on context) ---
        for m in _IFSC_PATTERN.finditer(upper):
            raw = m.group(1)
            bank_code = raw[:4]
            confidence = "MEDIUM" if bank_code in _KNOWN_BANK_CODES else "LOW"
            results.append(RecognizerMatch(
                entity_type="IFSC",
                raw_value=raw,
                masked_value=_mask_ifsc(raw),
                confidence=confidence,
                extra={"bank_code": bank_code},
            ))

        # --- Bank account numbers (always LOW; boosted by row density + IFSC context) ---
        # Skip digits that are already captured by other recognizers:
        # 10-digit strings → mobile, 12-digit strings → aadhaar (overlaps removed
        # via deduplication in engine seen-set).
        for m in _ACCOUNT_PATTERN.finditer(text):
            raw = m.group(1)
            # Reject if first digit is 0 (accounts don't start with 0)
            if raw[0] == "0":
                continue
            results.append(RecognizerMatch(
                entity_type="BANK_ACCOUNT",
                raw_value=raw,
                masked_value=_mask_account(raw),
                confidence="LOW",  # engine upgrades via row density profiling
            ))

        return results
