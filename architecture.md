# Architecture — PII/PHI Compliance Scanner

**Last updated:** 2026-08-02
**Scope:** v1 only (CSV/XLSX ingestion, Indian identifier recognizers). Later formats and Presidio NER are noted but not designed in detail until validated by design partners (see phases.md).

## Design principle

Detection engine is not the differentiator. Ingestion-to-source-location mapping, accuracy rigor, and the verifiable local-only execution model are. Architecture decisions below optimize for those, not for maximal format coverage on day one.

## High-level flow

```
[Input: file/folder path]
        |
        v
  [Ingestion layer]  -- normalizes to (text_chunk, source_location) pairs
        |
        v
  [Recognizer registry] -- pattern match + checksum validation per identifier type
        |
        v
  [Confidence tiering] -- HIGH (checksum passed) / MEDIUM (format only) / LOW (weak signal)
        |
        v
  [Report generator] -- CSV/JSON, one row per finding: file, sheet, cell, entity_type, value_masked, confidence
```

No step in this pipeline makes a network call. This is enforced, not assumed — see "Trust architecture" below.

## Components

### 1. Ingestion layer
- v1: CSV (stdlib `csv`) and XLSX (`openpyxl`, read-only mode for memory efficiency).
- Each parser yields chunks tagged with exact source location: `(file_path, sheet_name, cell_ref)` for XLSX, `(file_path, row_number, column_name)` for CSV.
- Deferred to later phases: DOCX (`python-docx`), PDF (`pdfplumber`), OCR (`pytesseract`) — not designed in detail yet; format choice for each should be driven by what design partners' actual data mix looks like, not built speculatively.

### 2. Detection layer
- **Indian identifier recognizers (our differentiator):** implemented as standalone pattern + validator functions, independent of any NLP framework so they can be unit-tested in isolation.
  - Aadhaar: 12-digit pattern + Verhoeff checksum algorithm.
  - PAN: `AAAAA9999A` structural pattern (4th character indicates holder type — validate, don't just regex-match the shape).
  - GSTIN: 15-char alphanumeric, embeds state code + PAN + checksum digit — validate the checksum, not just length/shape.
  - Mobile numbers: Indian numbering plan patterns (fewer false-positive traps than the identifiers above, still worth basic validation e.g. valid prefix ranges).
- **Presidio integration:** used as the detection *framework* (recognizer registry, entity resolution, anonymizer for later redaction phase) rather than reimplementing that plumbing. Our recognizers register as Presidio `PatternRecognizer` subclasses so they compose with Presidio's own US/EU recognizers if ever needed.
  - Note: Presidio's NLP-based entities (PERSON, LOCATION via spaCy) are **not** enabled in v1. Multilingual/transliterated Indian names in spreadsheets is a genuinely harder detection problem than structured identifiers and would currently produce a much higher false-positive/negative rate — shipping it prematurely undermines trust in the whole tool. Revisit only after identifier detection is validated and only with its own labeled test corpus.

### 3. Confidence tiering
Every finding ships with a confidence tier, not a bare "found/not found":
- **HIGH** — pattern matched *and* checksum validated (Aadhaar, PAN, GSTIN).
- **MEDIUM** — pattern matched, no checksum available (mobile numbers) or checksum validator not yet implemented.
- **LOW** — weak/contextual signal only.

This exists because false negatives on a compliance tool are a liability, and overclaiming certainty is worse than admitting a weaker signal. Never collapse this into a single boolean in the report.

### 4. Reporting layer
- CSV and JSON output. One row per finding: `file, location, entity_type, masked_value_preview, confidence_tier`.
- Rollup summary: counts by entity type, by file, top-risk files.
- No PDF report generation in v1 — that's presentation polish, not detection value; revisit once a design partner asks for it specifically.

### 5. CLI
- Single entrypoint (`click` or `typer`): `scan <path> --output report.csv`.
- No web dashboard, no Docker packaging in v1 (see phases.md — these are explicitly deferred until a design partner is actually using the CLI and asking for them).

## Trust architecture (non-negotiable, built in from day one)

- No telemetry of scanned content, file names, or findings, ever, by default or otherwise.
- No dependency in the scanning path may make an outbound network call. This should be checkable by running the scanner with network access physically disabled and confirming identical output.
- This is the entire value proposition against Nightfall/Macie/Purview. It is verified by inspection, not asserted in marketing copy.

## Tech stack (v1)

| Concern | Choice | Rationale |
|---|---|---|
| Language | Python 3.12 | Presidio, openpyxl, pandas ecosystem |
| Detection framework | Presidio (`presidio-analyzer`) | Mature, MIT-licensed, don't rebuild recognizer plumbing |
| Custom recognizers | Presidio `PatternRecognizer` subclasses | Composability with upstream, contribution path back to Presidio |
| XLSX parsing | `openpyxl` (read-only mode) | Cell-level location metadata, no pandas overhead for large sheets |
| CSV parsing | stdlib `csv` | No dependency needed |
| CLI | `click` or `typer` | Standard, low-friction |

## Deferred / not yet designed

Dashboard, Docker packaging, redaction/masking output, DOCX/PDF/OCR ingestion, multi-language NER, RBAC, scheduled scans, Google Drive/email/Slack integrations. These are real parts of the long-term product but are intentionally undesigned here — see phases.md for when each gets revisited and what evidence should trigger designing it.
