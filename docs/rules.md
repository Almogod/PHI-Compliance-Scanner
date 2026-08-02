# Rules — PII/PHI Compliance Scanner

**Last updated:** 2026-08-02
**Purpose:** Guardrails for anyone (human or AI agent) working on this codebase. These exist because this is a compliance-adjacent product where the failure modes (false negatives, overclaiming, data leakage) have real consequences, not just "bug reports."

## Hard rules — never violate

1. **No outbound network call in the scanning path.** Ever. Not for telemetry, not for "checking for updates," not for anything. If a dependency introduces one, remove or vendor around it. This is checked by running scans with network access disabled; any regression here is a P0.
2. **No PII is logged, cached, or persisted outside the report the user explicitly requested.** Scanned content lives in memory for the duration of the scan and nowhere else.
3. **No recognizer ships without a validator, where a validator exists.** Aadhaar, PAN, and GSTIN have public checksum algorithms — a recognizer that only regex-matches shape without validating the checksum is not done. Mobile numbers and any identifier without a checksum must be explicitly tagged MEDIUM/LOW confidence, never HIGH.
4. **No recognizer ships without a labeled test corpus** containing both true positives and known hard-negatives (e.g., a 12-digit number that fails the Verhoeff check must not fire as Aadhaar). Corpus is synthetic — never use real PII, even "just for testing."
5. **No legal/compliance certification language** ("DPDP compliant," "audit-ready," "guarantees compliance") anywhere in code comments, CLI output, report templates, or docs without a lawyer reviewing the specific text. Default assumption: don't say it.
6. **No regulatory date, deadline, or penalty figure** goes into product copy without being checked against the primary source (Gazette notification / MeitY), not a vendor blog. Vendor blogs (including ones cited in project research) are a starting point, not a source of truth.
7. **Every finding in a report carries an explicit confidence tier.** Never collapse detection results into a bare boolean "found." A false sense of certainty is worse than an honest "possible match."

## Build-order rules

8. **Do not add a new input format** (DOCX, PDF, OCR, images) until it's justified by an actual design partner's real data mix, not because it was on the original wishlist. Check phases.md before starting new format work.
9. **Do not add general NER (person names, addresses)** until identifier detection has its own proven accuracy numbers. These are different problems with different failure modes; don't let one hide behind the other's confidence.
10. **Do not build the dashboard, Docker packaging, or hosted layer** until someone is actually using the CLI. Infra work ahead of usage evidence is the most common way this kind of project stalls.
11. **Do not lock pricing or the open-core/paid split** until 2–3 design partners have said what they'd actually pay for. Revisit prd.md's open questions before any pricing decision.

## Code conventions

- Recognizers are standalone, unit-testable functions/classes independent of the ingestion layer — a recognizer should be testable by calling it with a string, no file I/O required.
- Type hints throughout; no bare `Any` on public functions.
- Every source-location tuple is explicit (`file_path`, plus format-specific location like `sheet+cell` or `row+column`) — never report a finding without being able to point at exactly where it came from.
- Prefer well-maintained dependencies (Presidio, openpyxl) over hand-rolled parsing, except where the differentiator explicitly requires custom logic (Indian identifier validators).

## Definition of done — for a recognizer

- [ ] Pattern implemented
- [ ] Checksum/validator implemented if one exists publicly
- [ ] Confidence tier assigned honestly (not defaulted to HIGH)
- [ ] Test corpus: true positives + hard negatives, committed alongside the recognizer
- [ ] Precision/recall run and recorded in memory.md
- [ ] No network call introduced

## When in doubt

Default to the more conservative option: lower confidence tier over higher, no legal claim over a claim, "ask a design partner" over "build it speculatively," and "check the primary source" over "trust the summary."
