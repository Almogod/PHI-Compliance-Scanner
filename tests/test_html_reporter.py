"""Tests for HTML Executive Audit Reporter."""
from pathlib import Path

from phi_scanner.engine import Finding
from phi_scanner.ingestion.base import SourceLocation
from phi_scanner.reporter import write_html


def test_write_html_report(tmp_path: Path) -> None:
    html_file = tmp_path / "audit_report.html"

    loc1 = SourceLocation(file_path=Path("docs/payroll.xlsx"), sheet_name="Sheet1", row=5, column="B")
    loc2 = SourceLocation(file_path=Path("docs/agreement.docx"), sheet_name=None, row=2, column="paragraph")

    findings = [
        Finding(entity_type="AADHAAR", masked_value="XXXX XXXX 1234", confidence="HIGH", location=loc1),
        Finding(entity_type="PAN", masked_value="XXXXX1234X", confidence="HIGH", location=loc2),
    ]

    write_html(findings, html_file, target_path_str="C:/data/workspace")

    assert html_file.exists()
    content = html_file.read_text(encoding="utf-8")

    assert "<title>PHI Compliance Audit Report</title>" in content
    assert "CRITICAL RISK" in content
    assert "AADHAAR" in content
    assert "PAN" in content
    assert "XXXX XXXX 1234" in content
    assert "payroll.xlsx" in content
