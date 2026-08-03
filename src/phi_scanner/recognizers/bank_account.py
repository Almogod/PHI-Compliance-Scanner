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
"""
from __future__ import annotations

import re

from .base import BaseRecognizer, RecognizerMatch


# ---------------------------------------------------------------------------
# Patterns
# ---------------------------------------------------------------------------

_IFSC_PATTERN = re.compile(
    r"(?<![A-Z0-9])([A-Z]{4}0[A-Z0-9]{6})(?![A-Z0-9])"
)

_ACCOUNT_PATTERN = re.compile(
    r"(?<!\d)(\d{9}|\d{11}|\d{12}|\d{13}|\d{14}|\d{15}|\d{16}|\d{17}|\d{18})(?!\d)"
)

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


def find_bank_account(text: str) -> list[RecognizerMatch]:
    rec = BankAccountRecognizer()
    return [m for m in rec.find(text) if m.entity_type == "BANK_ACCOUNT"]


def find_ifsc(text: str) -> list[RecognizerMatch]:
    rec = BankAccountRecognizer()
    return [m for m in rec.find(text) if m.entity_type == "IFSC"]


class BankAccountRecognizer(BaseRecognizer):
    """Recognizes IFSC codes and bank account numbers."""

    entity_type = "IFSC"

    def find(self, text: str) -> list[RecognizerMatch]:
        results: list[RecognizerMatch] = []
        upper = text.upper()

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

        for m in _ACCOUNT_PATTERN.finditer(text):
            raw = m.group(1)
            if raw[0] == "0":
                continue
            results.append(RecognizerMatch(
                entity_type="BANK_ACCOUNT",
                raw_value=raw,
                masked_value=_mask_account(raw),
                confidence="LOW",
            ))

        return results
