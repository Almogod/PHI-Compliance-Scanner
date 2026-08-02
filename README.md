# PHI-Compliance-Scanner

Local-only PII/PHI compliance scanner for Indian identifiers — built for DPDP Act readiness.

**Zero cloud. Zero telemetry. Verifiable by inspection.**

## What it detects (v1)

| Identifier | Validation | Confidence |
|---|---|---|
| Aadhaar | Verhoeff checksum | HIGH / MEDIUM |
| PAN | Holder-type structural check | HIGH / MEDIUM |
| GSTIN | Public checksum algorithm + state code | HIGH / MEDIUM / LOW |
| Mobile (Indian) | Prefix range (no checksum) | MEDIUM only |

Every finding carries an explicit confidence tier — never a bare boolean (see `rules.md`).

## Quick start

```bash
# 1. Install
pip install -e ".[dev]"

# 2. Generate sample data
python sample_data/generate_sample.py

# 3. Scan
scan sample_data/ --output report.csv

# 4. JSON output
scan sample_data/ --output report.json

# 5. Only HIGH confidence findings
scan sample_data/ --min-confidence HIGH --output high_only.csv
```

## Run tests

```bash
pytest
```

## Project layout

```
src/phi_scanner/
  ingestion/      CSV + XLSX parsers (exact cell-level location)
  recognizers/    Aadhaar, PAN, GSTIN, Mobile with validation
  engine.py       Orchestration (no network calls)
  reporter.py     CSV + JSON output (masked values only)
  cli.py          scan <path> --output report.csv

tests/
  corpus/         Synthetic true positives + hard negatives
  test_*.py       Precision/recall tests per recognizer
```

## Legal notice

This tool finds pattern-matched personal data. It does not certify legal compliance,
constitute legal advice, or make any claim of DPDP compliance. See `rules.md §5`.