# Memory — PII/PHI Compliance Scanner

**Purpose:** Living log of decisions, validated/invalidated assumptions, and open questions. Update this after every significant conversation, pilot, or pivot — it's the source of truth for "why did we decide X," not prd.md or phases.md, which describe current state rather than history.

---

## Current status
**As of 2026-08-02:** Phase 6 (v2 Capabilities) Complete.
- Redaction Engine (`src/phi_scanner/redactor.py`) & `--redact-output` / `-r` CLI flag for CSV/XLSX sanitization.
- Expanded Identifier Support: Added Indian Voter ID (EPIC) & Indian Passport Number recognizers.
- Zero-Dependency Built-in Local Web Dashboard (`src/phi_scanner/dashboard.py`) & `--web` / `--gui` CLI flag.
- Production Air-Gapped `Dockerfile` & `.dockerignore` for containerized execution.
- 182/182 tests passing.






---

## Decisions log

**2026-08-02 — Scope narrowed from original plan**
Original brief proposed building ingestion for scanned PDFs/spreadsheets/images plus full Presidio NER plus dashboard plus Docker as a single MVP. Decided this is too wide for v1. Narrowed to: CSV/XLSX ingestion only, 4 Indian identifier recognizers (Aadhaar, PAN, GSTIN, mobile) with checksum validation, CLI-only output. Rationale: fastest path to something a real design partner can use and give feedback on; everything else deferred to evidence-driven phases. See phases.md.

**2026-08-02 — Regulatory timeline double-checked**
Original pitch cited "full penalty enforcement expected from May 2027" as the sole deadline (source: a single vendor blog). Checked against multiple current trackers — enforcement powers and the penalty regime (up to ₹250 crore/violation) reportedly activate in a Phase 2 around 13 November 2026, a year earlier than the full May 2027 compliance deadline. This meaningfully compresses the "build year" window. **Not yet verified against the actual Gazette/MeitY text** — do that before this appears in any external-facing material. Treat all dates in prd.md/phases.md as provisional until confirmed against a primary source.

**2026-08-02 — Buyer segment left unresolved on purpose**
Two candidate buyers (direct SME vs compliance-consultant-serving-SMEs) have different implications for pricing, dashboard needs, and report format. Deliberately not chosen yet — resolve via Phase 0 discovery conversations, not assumption.

**2026-08-02 — Detection engine explicitly deprioritized as "the differentiator"**
Decided the real differentiators are: ingestion-to-source-location mapping, accuracy rigor (test corpus + confidence tiering), and a verifiable no-network-call trust architecture — not the Indian identifier regex/checksums themselves, which are public algorithms a funded competitor could replicate quickly. Effort should be weighted accordingly (see architecture.md "Design principle").

---

## Validated assumptions
*(none yet — nothing has been tested with a real design partner)*

## Invalidated assumptions
*(none yet)*

## Open questions (carry forward until resolved)

- SME vs consultant buyer — target resolution: end of Phase 0.
- Is the Aadhaar/PAN/GSTIN detection itself the paid value, or is the audit-trail report format the thing people actually pay for? — target resolution: Phase 2–4.
- Will design partners provide even synthetic/structurally-similar data for testing, given sensitivity? — target resolution: Phase 2.
- Actual DPDP Phase 2/3 dates per primary source (not vendor blogs) — resolve before any external copy is written.

## Next actions
1. Run 8–10 customer discovery conversations (Phase 0).
2. Verify DPDP enforcement dates against the Gazette/MeitY notification directly.
3. Once buyer segment has a working hypothesis, begin Phase 1 (recognizer + ingestion build) per architecture.md.

---

## Update log
- 2026-08-02: File created, seeded with kickoff decisions and open questions.
- 2026-08-02: Phase 1 implementation complete.

---

## Phase 1 precision/recall & hardening (synthetic corpus, 2026-08-02)

| Recognizer | True Positives | Hard Negatives | Hardening & Resiliency Enhancements |
|---|---|---|---|
| Aadhaar | 100% | 0% FP | Supports dot, slash, underscore, pipe separators; +91 FP guard. |
| PAN | 100% | 0% FP | Handles spaced PANs ("ABC PD 1234 E"), mixed case; guards email & path FPs. |
| GSTIN | 100% | 0% FP | Checksum + state code 01–38; multi-value cell support. |
| Mobile | 100% | 0% FP | Handles parens, dots; guards currency (₹, INR, Rs.), timestamps, invoice IDs. |

### Engine & Ingestion Resilience Highlights
- **Text Normalizer (`normalizer.py`)**: Converts Excel float numbers (`9876543210.0` -> `9876543210`), cleans zero-width Unicode/smart quotes, and splits multi-value cells.
- **Context Signals (`context.py`)**: Column header and inline label detection boosts confidence (e.g. `aadhaar_no` column boosts MEDIUM -> HIGH).
- **Masked Identifier Detection**: Flags partially-masked identifiers (e.g., `XXXX XXXX 1234` or `XXXXX1234X`) as explicit exposure risks (`AADHAAR_MASKED`, `PAN_MASKED`).
- **Multi-encoding CSV Ingestion**: Automatic fallback from `utf-8-sig` -> `latin-1` -> `cp1252`.

All numbers on synthetic corpus only. Real-world recall is unvalidated until Phase 2 design partner runs.

## Phase 1 decisions log

**2026-08-02 — Resilience and Hardening Refactor**
Added dedicated text normalisation and context boosting modules to eliminate false negatives caused by Excel float conversions, multi-value cells, formatting variations (dots, parens, spaces), and zero-width unicode noise, while adding strict context guards against currency, invoice IDs, and email false positives.

