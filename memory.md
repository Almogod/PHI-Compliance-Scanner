# Memory — PII/PHI Compliance Scanner

**Purpose:** Living log of decisions, validated/invalidated assumptions, and open questions. Update this after every significant conversation, pilot, or pivot — it's the source of truth for "why did we decide X," not prd.md or phases.md, which describe current state rather than history.

---

## Current status
**As of 2026-08-02:** Phase 1 complete. CLI ships and passes all 116 tests.
Phase 0 (customer discovery) should run in parallel with Phase 2 (design partner pilot).

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

## Phase 1 precision/recall (synthetic corpus, 2026-08-02)

| Recognizer | True Positives | Hard Negatives | HIGH-confidence FP rate | Notes |
|---|---|---|---|---|
| Aadhaar | 10/10 (100%) | 7 | 0% | Verhoeff checksum. Fixed +91-prefix FP. |
| PAN | 10/10 (100%) | 6 | 0% | Holder-type structural check. |
| GSTIN | 6/6 (100%) | 6 | 0% | Public checksum + state code 01–38. |
| Mobile | 8/8 (100%) | 6 | 0% | No checksum; capped at MEDIUM. |

All numbers on synthetic corpus only. Real-world recall is unvalidated until Phase 2 design partner runs.

## Phase 1 decisions log

**2026-08-02 — verhoeff_check_digit implemented as brute-force search over validate()**
The algebraic generation formula (c = D[c][P[(i+1)%8][d]] approach) produced wrong digits for some prefixes (e.g. "34567890123" generated 6 instead of correct 8). Root cause not fully traced — the brute-force search over all 10 candidates is simpler, always correct, and fast enough for test corpus generation. The validate() function is the ground truth; generate is only used offline.

**2026-08-02 — +91 country-code prefix causes Aadhaar false positives**
"+91 8765432109" after separator stripping becomes "918765432109" — 12 digits starting with 9, matching the Aadhaar pattern. Fixed by stripping known phone prefixes (+91, bare 91, trunk 0) from stripped text before Aadhaar pattern matching. Added regression note: this class of false positive should be included in the hard-negative corpus for future design partner testing.
