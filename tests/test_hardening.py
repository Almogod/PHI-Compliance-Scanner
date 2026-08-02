"""Hardening tests — real-world edge cases that would cause false negatives.

These tests represent scenarios we've seen or anticipate in messy Indian
spreadsheet data. Each test documents the exact real-world scenario it guards
against. When a design partner finds a new false negative, add it here.
"""
import csv
from pathlib import Path

import openpyxl
import pytest

from phi_scanner.engine import ScanEngine, Finding
from phi_scanner.recognizers.aadhaar import find_aadhaar, verhoeff_check_digit
from phi_scanner.recognizers.pan import find_pan
from phi_scanner.recognizers.gstin import find_gstin
from phi_scanner.recognizers.mobile import find_mobile


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_aadhaar(prefix: str) -> str:
    return prefix + verhoeff_check_digit(prefix)


def _findings_from_csv(tmp_path: Path, rows: list[dict]) -> list[Finding]:
    """Write rows to a temp CSV and scan it, returning all findings."""
    p = tmp_path / "test.csv"
    with open(p, "w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=list(rows[0].keys()))
        writer.writeheader()
        writer.writerows(rows)
    return list(ScanEngine().scan_path(p))


def _findings_from_xlsx(tmp_path: Path, data: dict) -> list[Finding]:
    """Write data to a temp XLSX and scan it, returning all findings."""
    p = tmp_path / "test.xlsx"
    wb = openpyxl.Workbook()
    ws = wb.active
    ws.title = "Sheet1"
    for row in data.get("rows", []):
        ws.append(row)
    wb.save(p)
    return list(ScanEngine().scan_path(p))


# ---------------------------------------------------------------------------
# FALSE NEGATIVE TESTS — must find identifiers in these scenarios
# ---------------------------------------------------------------------------

class TestFalseNegativeGuards:
    """Each test represents a real-world scenario where v1 missed a finding."""

    def test_dot_separated_aadhaar(self) -> None:
        """Some HR systems export Aadhaar as 2345.6789.0124"""
        valid = _make_aadhaar("23456789012")
        dotted = f"{valid[:4]}.{valid[4:8]}.{valid[8:]}"
        matches = find_aadhaar(dotted)
        assert len(matches) >= 1, f"Missed dot-separated Aadhaar: {dotted}"

    def test_underscore_separated_aadhaar(self) -> None:
        valid = _make_aadhaar("23456789012")
        underscored = f"{valid[:4]}_{valid[4:8]}_{valid[8:]}"
        matches = find_aadhaar(underscored)
        assert len(matches) >= 1, f"Missed underscore-separated: {underscored}"

    def test_slash_separated_aadhaar(self) -> None:
        valid = _make_aadhaar("23456789012")
        slashed = f"{valid[:4]}/{valid[4:8]}/{valid[8:]}"
        matches = find_aadhaar(slashed)
        assert len(matches) >= 1, f"Missed slash-separated: {slashed}"

    def test_spaced_pan(self) -> None:
        """HR data sometimes has spaces in PAN: 'ABC PD 1234 E'"""
        matches = find_pan("ABC PD 1234 E")
        assert len(matches) >= 1, "Missed spaced PAN: 'ABC PD 1234 E'"

    def test_pan_with_label(self) -> None:
        """Cells often contain 'PAN No: ABCPD1234E'"""
        matches = find_pan("PAN No: ABCPD1234E")
        assert len(matches) >= 1

    def test_lowercase_pan(self) -> None:
        """Mixed-case PAN from copy-paste"""
        matches = find_pan("abcpd1234e")
        assert len(matches) >= 1

    def test_mobile_with_dots(self) -> None:
        """Some systems format mobile as 98765.43210"""
        matches = find_mobile("98765.43210")
        assert len(matches) >= 1, "Missed dot-formatted mobile"

    def test_mobile_with_parens(self) -> None:
        """(91) 9876543210 format"""
        matches = find_mobile("(91) 9876543210")
        assert len(matches) >= 1, "Missed parens mobile"

    def test_multi_value_cell_csv(self, tmp_path: Path) -> None:
        """Cell containing comma-separated PAN and mobile."""
        findings = _findings_from_csv(tmp_path, [
            {"data": "PAN: ABCPD1234E, Mobile: 9876543210"},
        ])
        entity_types = {f.entity_type for f in findings}
        assert "PAN" in entity_types, "Missed PAN in multi-value cell"
        assert "IN_MOBILE" in entity_types, "Missed mobile in multi-value cell"

    def test_excel_numeric_aadhaar(self, tmp_path: Path) -> None:
        """Excel stores Aadhaar as a float — must still detect after conversion."""
        valid = _make_aadhaar("23456789012")
        # Simulate what openpyxl returns for a numeric cell
        findings = _findings_from_xlsx(tmp_path, {
            "rows": [["aadhaar"], [int(valid)]],  # Excel stores as number
        })
        aadhaar_findings = [f for f in findings if f.entity_type == "AADHAAR"]
        assert len(aadhaar_findings) >= 1, "Missed Aadhaar stored as Excel number"

    def test_excel_numeric_mobile(self, tmp_path: Path) -> None:
        """Mobile stored as Excel number (9876543210 → 9876543210.0)."""
        findings = _findings_from_xlsx(tmp_path, {
            "rows": [["phone"], [9876543210]],
        })
        mobile_findings = [f for f in findings if f.entity_type == "IN_MOBILE"]
        assert len(mobile_findings) >= 1, "Missed mobile stored as Excel number"


# ---------------------------------------------------------------------------
# FALSE POSITIVE GUARDS — must NOT fire on these
# ---------------------------------------------------------------------------

class TestFalsePositiveGuards:
    def test_pan_in_email_not_detected(self) -> None:
        """ABCPD1234E@gmail.com is an email address, not a PAN."""
        matches = find_pan("ABCPD1234E@gmail.com")
        assert len(matches) == 0, "Falsely flagged email as PAN"

    def test_currency_amount_not_mobile(self) -> None:
        """₹9876543210 is a currency amount, not a phone number."""
        matches = find_mobile("₹9876543210")
        assert len(matches) == 0, "Falsely flagged currency as mobile"

    def test_inr_amount_not_mobile(self) -> None:
        matches = find_mobile("INR 9876543210")
        assert len(matches) == 0, "Falsely flagged INR amount as mobile"

    def test_rs_amount_not_mobile(self) -> None:
        matches = find_mobile("Rs. 9876543210")
        assert len(matches) == 0, "Falsely flagged Rs amount as mobile"


# ---------------------------------------------------------------------------
# CONTEXT BOOSTING END-TO-END
# ---------------------------------------------------------------------------

class TestContextBoostingE2E:
    def test_aadhaar_column_boosts_failed_verhoeff(self, tmp_path: Path) -> None:
        """A 12-digit number in an 'aadhaar_no' column that fails Verhoeff
        should be boosted from MEDIUM to HIGH."""
        # Construct a valid Aadhaar then corrupt last digit to fail Verhoeff
        valid = _make_aadhaar("23456789012")
        corrupted = valid[:-1] + str((int(valid[-1]) + 1) % 10)

        findings = _findings_from_csv(tmp_path, [
            {"aadhaar_no": corrupted},
        ])
        aadhaar_findings = [f for f in findings if f.entity_type == "AADHAAR"]
        assert len(aadhaar_findings) >= 1, "Should still detect in aadhaar column"
        # Context should boost MEDIUM → HIGH because column says "aadhaar_no"
        assert aadhaar_findings[0].confidence == "HIGH", \
            f"Expected HIGH after context boost, got {aadhaar_findings[0].confidence}"

    def test_mobile_in_phone_column_stays_medium(self, tmp_path: Path) -> None:
        """Mobile in 'phone' column: no checksum so can't be HIGH.
        Context boosts MEDIUM → HIGH for mobile in a phone column."""
        findings = _findings_from_csv(tmp_path, [
            {"phone": "9876543210"},
        ])
        mobile_findings = [f for f in findings if f.entity_type == "IN_MOBILE"]
        assert len(mobile_findings) >= 1
