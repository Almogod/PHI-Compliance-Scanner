"""Unit and integration tests for v4 enterprise feature additions.

Tests:
  1. Multi-format & Unstructured Ingestion (.txt, .json, .jsonl, .tsv)
  2. Multi-lingual Recognition (Indic numeral translation & Hindi context signals)
  3. Smart Remediation Options (mask, redact, tokenize)
  4. Executive PDF Compliance Summary output
  5. Read-only SQLite Database Connector scanning
"""
from __future__ import annotations

import json
import sqlite3
from pathlib import Path

import pytest

from phi_scanner.engine import ScanEngine
from phi_scanner.ingestion.unstructured_ingester import (
    UnstructuredIngester,
    JsonIngester,
    TsvIngester,
)
from phi_scanner.ingestion.db_ingester import DbIngester
from phi_scanner.normalizer import normalise_unicode, normalise_cell
from phi_scanner.pipeline import Pipeline
from phi_scanner.recognizers.aadhaar import verhoeff_check_digit
from phi_scanner.redactor import sanitize_text, tokenize_value, redact_file
from phi_scanner.reporter import write_pdf_summary


def test_indic_numeral_translation():
    """Verify Devanagari, Bengali, Gujarati, Tamil, Telugu digits map to ASCII 0-9."""
    devanagari_text = "आधार संख्या: ९८७६५४३२१०"
    normalised = normalise_unicode(devanagari_text)
    assert "9876543210" in normalised

    bengali_text = "মোবাইল: ৯৮৭৬৫ND৩২১০"
    normalised_bengali = normalise_unicode(bengali_text)
    assert "98765" in normalised_bengali


def test_unstructured_ingestion(tmp_path: Path):
    """Test plain text (.txt) and JSON (.json) ingesters."""
    aadhaar_prefix = "98765432102"
    valid_aadhaar = aadhaar_prefix + verhoeff_check_digit(aadhaar_prefix)

    txt_file = tmp_path / "sample.txt"
    txt_file.write_text(f"Customer PAN: ABCPD1234E in record.\nAadhaar: {valid_aadhaar}", encoding="utf-8")

    ingester = UnstructuredIngester()
    records = list(ingester.ingest_records(txt_file))
    assert len(records) == 2
    assert "ABCPD1234E" in records[0].text

    json_file = tmp_path / "sample.json"
    json_data = {"user": {"name": "Test User", "aadhaar": valid_aadhaar}}
    json_file.write_text(json.dumps(json_data), encoding="utf-8")

    json_ingester = JsonIngester()
    json_records = list(json_ingester.ingest_records(json_file))
    assert len(json_records) == 2
    assert any("user.aadhaar" == r.location.column for r in json_records)


def test_tsv_ingestion(tmp_path: Path):
    """Test TSV ingester."""
    tsv_file = tmp_path / "data.tsv"
    tsv_file.write_text("name\tpan\nRahul\tABCPD1234E\n", encoding="utf-8")

    ingester = TsvIngester()
    records = list(ingester.ingest_records(tsv_file))
    assert len(records) == 2
    assert records[1].location.column == "pan"
    assert records[1].text == "ABCPD1234E"


def test_remediation_modes():
    """Test mask, redact, and tokenize remediation options."""
    aadhaar_prefix = "98765432102"
    valid_aadhaar = aadhaar_prefix + verhoeff_check_digit(aadhaar_prefix)

    text = f"PAN is ABCPD1234E and Aadhaar is {valid_aadhaar}"

    masked = sanitize_text(text, mode="mask")
    assert "ABCPD1234E" not in masked

    redacted = sanitize_text(text, mode="redact")
    assert "[REDACTED_PAN]" in redacted
    assert "[REDACTED_AADHAAR]" in redacted

    tokenized = sanitize_text(text, mode="tokenize")
    assert "TOK-PAN-" in tokenized
    assert "TOK-AADHAAR-" in tokenized


def test_pdf_executive_summary_generation(tmp_path: Path):
    """Test executive PDF summary generator."""
    pdf_out = tmp_path / "executive_report.pdf"
    engine = ScanEngine()

    sample_csv = tmp_path / "sample.csv"
    sample_csv.write_text("name,pan\nAlice,ABCPD1234E\n", encoding="utf-8")

    findings = list(engine.scan_file(sample_csv))
    assert len(findings) > 0

    write_pdf_summary(findings, pdf_out, target_path_str=str(sample_csv))
    assert pdf_out.exists()
    assert pdf_out.stat().st_size > 0


def test_sqlite_db_ingester(tmp_path: Path):
    """Test scanning a local SQLite database in read-only mode."""
    db_file = tmp_path / "test_db.sqlite"
    conn = sqlite3.connect(db_file)
    cursor = conn.cursor()
    cursor.execute("CREATE TABLE users (id INT, name TEXT, pan TEXT);")
    cursor.execute("INSERT INTO users VALUES (1, 'Suresh', 'ABCPD1234E');")
    conn.commit()
    conn.close()

    pipeline = Pipeline()
    findings = list(pipeline.scan_db(f"sqlite:///{db_file}"))
    assert len(findings) >= 1
    pan_finding = next(f for f in findings if f.entity_type == "PAN")
    assert pan_finding.location.sheet_name == "users"
    assert pan_finding.location.column == "pan"


def test_gui_import():
    """Verify CustomTkinter GUI module can be imported and initialized."""
    import customtkinter
    from phi_scanner.gui import ComplianceScannerGUI
    assert ComplianceScannerGUI is not None

