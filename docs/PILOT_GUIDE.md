# PHI/PII Scanner — Design Partner Pilot Guide

Welcome to the PHI Compliance Scanner pilot. This tool scans local spreadsheets (CSV and XLSX) for Indian PII identifiers (**Aadhaar, PAN, GSTIN, Mobile Numbers**) to help evaluate DPDP Act compliance readiness.

---

## 🔒 Trust Architecture: 100% Local & No-Network Guaranteed

Security and data privacy are paramount:
- **Zero outbound network calls:** The engine performs pattern matching and deterministic mathematical checksum validation (Verhoeff for Aadhaar, weighted modular sum for GSTIN) entirely offline.
- **In-Memory processing:** File contents exist in RAM only during scanning and are never saved, cached, or transmitted anywhere.
- **Masked reporting:** Output reports automatically redact sensitive characters (e.g. `XXXX XXXX 1234` or `XXXXX1234X`).

### How to verify no-network execution (Security & IT Teams)
You can disconnect your network connection entirely before running the scanner, or run it behind a strict firewall/sandbox block.

---

## 🚀 Quickstart: Running a Scan

### 1. Installation
Ensure Python 3.11+ is installed. Install the local package:

```powershell
pip install -e .
```

### 2. Run a Scan
Point `scan` to a single spreadsheet or an entire folder of data files:

```powershell
# Scan a single file and save results to report.csv
scan C:\path\to\data_export.xlsx --output report.csv

# Scan an entire directory recursively using 8 worker threads
scan C:\path\to\documents\ --workers 8 --output company_findings.csv

# Generate an Executive Audit Summary JSON file for compliance reporting
scan C:\path\to\documents\ --output company_findings.csv --summary-file audit_summary.json

# Optional: Export in JSON format
scan C:\path\to\documents\ --output company_findings.json --format json

# Optional: Filter for HIGH-confidence findings only (checksum validated)
scan C:\path\to\documents\ --min-confidence HIGH --output high_confidence_findings.csv
```

---

## 📊 Understanding Findings & Confidence Tiers

The report CSV lists exact cell-level provenance so your team can locate and remediate exposed identifiers:

| Field | Description | Example |
|---|---|---|
| `file` | Path to the scanned file | `C:\data\payroll.xlsx` |
| `sheet` | Sheet name (XLSX only) | `July2026` |
| `row` | Row number | `14` |
| `column` | Column header or letter | `C` or `aadhaar_no` |
| `entity_type` | Detected PII identifier | `AADHAAR`, `PAN`, `GSTIN`, `IN_MOBILE` |
| `masked_value` | Redacted identifier preview | `XXXX XXXX 4321` |
| `confidence` | Validation certainty | `HIGH`, `MEDIUM`, `LOW` |

### Confidence Tier Meanings
- **`HIGH`**: Full pattern match **AND** passed mathematical checksum validation (Verhoeff for Aadhaar, public algorithm for GSTIN) or holder-type structural check (PAN).
- **`MEDIUM`**: Pattern matched but checksum failed (possible typo/transcription error in data) OR identifier lacks checksum (Mobile numbers).
- **`LOW`**: Partial shape match or unrecognized state code in GSTIN.

---

## 📝 Providing Pilot Feedback

If the scanner flags a false positive (something reported that isn't PII) or misses an identifier (false negative), please use `docs/FEEDBACK_TEMPLATE.csv` to notify us. Every reported case will be added to our permanent regression test suite.
