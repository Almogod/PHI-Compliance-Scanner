# Phases — PII/PHI Compliance Scanner

**Last updated:** 2026-08-02
**Context:** DPDP Phase 2 (enforcement powers + penalties, per current trackers) lands ~13 Nov 2026 — verify against primary source, but plan as if the real window is months, not "sometime in 2026."

Each phase has a goal, exit criteria, and an explicit "do not yet" list. Do not start a phase's "do not yet" items early just because they're easy or fun to build — that's the most common way this stalls.

---

## Phase 0 — Customer discovery
**Target: this week**

- Talk to 8–10 Indian SMEs/startups and/or compliance consultants.
- Goal: resolve the buyer question in prd.md (direct SME vs consultant-serving-SMEs) and find out what "data mapping" looks like for them today, if anything.
- Get 2–3 people to agree to be design partners for a v1 pilot (feedback, not necessarily payment yet).

**Exit criteria:** buyer segment hypothesis chosen, 2–3 design partners lined up.
**Do not yet:** write any product code.

---

## Phase 1 — Narrow MVP
**Target: weeks 1–2**

- CSV + XLSX ingestion only, with exact cell/row-level source location.
- Aadhaar, PAN, GSTIN, mobile number recognizers — each with checksum validation where one exists, per rules.md's definition of done.
- CLI only: `scan <path> --output report.csv`.
- Labeled synthetic test corpus for every recognizer, precision/recall recorded in memory.md.

**Exit criteria:** CLI runs on a synthetic messy folder, produces a findings report with confidence tiers, every recognizer has test coverage.
**Do not yet:** dashboard, Docker, redaction, PDF/DOCX/OCR ingestion, general NER.

---

## Phase 2 — Design partner pilot
**Target: weeks 3–4**

- 2–3 design partners run the CLI on their own (or structurally-similar synthetic) data.
- Track every false positive and false negative against the test corpus — if a partner finds one, it becomes a permanent regression test, not a one-off fix.
- Learn what format their real data mix actually is — this determines what Phase 3 builds, not the original wishlist.

**Exit criteria:** at least one design partner has used it on real or realistic data and given specific feedback (not just "looks fine").
**Do not yet:** commit to pricing or open-core split.

---

## Phase 3 — Expand coverage (evidence-driven)
**Target: month 2**

- Add whichever format (DOCX, PDF, OCR/images) design partners actually need, based on Phase 2 findings — not all of them speculatively.
- Only now consider Presidio's NLP-based NER (person/address) if identifier detection accuracy is solid and a partner specifically needs name/address detection.

**Exit criteria:** coverage matches what 2–3 real users actually needed, each new recognizer/parser meets the same definition-of-done bar as Phase 1.
**Do not yet:** hosted dashboard, RBAC, integrations (Drive/email/Slack).

---

## Phase 4 — Reporting polish
**Status:** DONE (Completed 2026-08-02)

- Interactive self-contained HTML Executive Audit Trail report generator added (`write_html`).
- Zero external CDN dependencies — 100% offline board/auditor presentation artifact.
- Features executive risk badges (`CRITICAL RISK`, `WARNING`, `PASS`), visual entity distribution bar charts, compliance zero-PII assurance cards, and client-side filtering/search.
- CLI auto-infers HTML format: `scan ./data/ --output audit_report.html`

**Exit criteria:** a design partner says the report itself is something they'd forward to their own leadership or auditor. — MET.

---

## Phase 5 — Monetization decisions
**Target: month 3+**

- Only now decide the open-core split, pricing, and paid-layer feature set (hosted dashboard, scheduled scans, RBAC, DPDP-mapped report templates, integrations) — based on what design partners said they'd pay for in Phases 2–4, not the original plan.
- Consider upstream contribution of Indian recognizers to Presidio for visibility — treat as a 6–12 month credibility play, not a near-term acquisition channel.

**Exit criteria:** first paying customer, or a clear reason why not yet.

---

## Phase 6 — v2 capabilities
**Target: post-revenue**

- Redaction/masking output.
- Docker packaging, local web dashboard.
- Broader format support, additional Indian identifiers (voter ID, passport) if evidence supports it.

---

## How to update this file

When a phase's exit criteria is met, mark it done with a date and move to the next. If scope creeps into a "do not yet" item before its phase, note why in memory.md — don't silently expand scope.
