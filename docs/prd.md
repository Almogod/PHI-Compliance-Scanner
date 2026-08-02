# PRD — Format-Agnostic PII/PHI Compliance Scanner

**Status:** Pre-build / customer discovery
**Last updated:** 2026-08-02

## Problem

Indian organizations preparing for DPDP Act enforcement need to answer one question cheaply and often: *"where in our messy pile of files does personal data actually live?"* Most have no data mapping process today. Existing tools either assume clean text input (Presidio) or require sending data to a cloud API (Nightfall, Google DLP, AWS Macie, Microsoft Purview). Nobody serves the specific case of messy, mixed-format, real-world files scanned entirely on the user's own machine.

**Regulatory context (verify against primary source before quoting externally):** DPDP Rules were notified 13 Nov 2025. Multiple current trackers report enforcement powers and the penalty regime (up to ₹250 crore per violation) activating in Phase 2 on **13 November 2026** — a year before the 13 May 2027 full-compliance deadline. This means the real sales window before penalties are live is roughly the next few months, not "sometime in 2026." Confirm against the Gazette text / MeitY notification before this appears in any customer-facing material.

## Buyer — unresolved, must validate before scoping past v1

Two plausible buyers with different requirements. Do not commit to one without customer discovery:

1. **Direct SME/startup** — buys a tool to self-serve data mapping. Wants simplicity, low price, no learning curve.
2. **Compliance consultant / auditor serving many SMEs** — buys a tool to make client engagements faster. Wants white-label output, batch scanning across clients, higher price tolerance, less hand-holding.

These imply different pricing, dashboard requirements, and report formats. Resolve via 8–10 discovery conversations before Phase 3 (see phases.md).

## Goals (v1)

- Scan CSV/XLSX files and detect Indian identifiers (Aadhaar, PAN, GSTIN, mobile numbers) with checksum-validated confidence, not regex guesses.
- Map every finding back to exact file + sheet + cell.
- Produce a findings report (CSV/JSON) usable by a non-technical compliance owner.
- Run entirely locally — zero outbound network calls in the scanning path, verifiable by inspection.

## Non-goals (v1)

- Scanned PDFs / OCR / images.
- Redaction or masking.
- Hosted dashboard, RBAC, scheduling.
- General NER (person names, addresses) via Presidio's spaCy pipeline — deferred until identifier detection is proven accurate, since multilingual Indian name/address NER is a materially harder problem than pattern-based identifiers.
- Any "DPDP compliant" or similar legal-compliance claim in product copy. This is not a legal product and must not imply legal certification without counsel review.

## User stories (v1)

- As a compliance owner, I point the CLI at a folder of spreadsheets and get a report of every Aadhaar/PAN/GSTIN/mobile number found, with file/sheet/cell location.
- As a security-conscious buyer, I can verify (by reading the code or watching network traffic during a demo) that no scanned content ever leaves the machine.
- As a design partner, I can tell the team a finding is wrong (false positive/negative) and see it tracked against a real test corpus, not just anecdotally fixed.

## Success metrics (v1, pre-revenue)

- Precision/recall per recognizer measured against a labeled synthetic test corpus (target: >95% precision on checksum-validated identifiers; recall tracked and reported honestly rather than assumed).
- 2–3 design partners actually run it on their own data and give usable feedback.
- Zero confirmed outbound network calls during any scan (this is a hard requirement, not an aspiration).

## Explicit non-claims

Do not describe this product externally as "DPDP compliant," "audit-ready," or similar without a lawyer reviewing report templates and marketing copy. The tool finds pattern-matched personal data; it does not certify legal compliance.

## Open questions

- SME vs consultant buyer (see above).
- Whether Aadhaar/PAN/GSTIN pattern+checksum detection alone is enough value to pay for, or whether the report/audit-trail format is the actual purchased artifact.
- Whether design partners will provide even synthetic/structurally-similar data for testing, given the sensitivity of what we're asking to scan.
