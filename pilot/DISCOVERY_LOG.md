# Phase 2 — Design Partner Pilot & Discovery Log

## Pilot Objectives & Exit Criteria
- **Goal:** Execute CLI scans with 2–3 design partners on real or realistic synthetic data.
- **Key Tracking:** Log every FP and FN directly into `tests/test_pilot_regressions.py` via `pilot/ingest_feedback.py`.
- **Data Mix Discovery:** Determine actual user format split (CSV vs XLSX vs legacy `.xls` vs PDF/DOCX) to prioritize Phase 3 scope.
- **Exit Criteria:** At least 1 design partner has run the CLI on realistic data and provided specific actionable feedback.

---

## 👥 Candidate Design Partners

| Partner ID | Segment / Profile | Status | Primary Data Format | Feedback Received |
|---|---|---|---|---|
| `PARTNER_01` | Mid-market Healthcare Ops / Clinic Chain | Contacted | XLSX (Multi-sheet patient exports) | Pending |
| `PARTNER_02` | FinTech / NBFC Compliance Team | Contacted | CSV (User KYC dump) | Pending |
| `PARTNER_03` | Data Protection / Legal Auditor | Contacted | Mixed CSV/XLSX | Pending |

---

## 📈 Partner Feedback & Regression Tracking

| Date | Partner | Type (FP/FN) | Entity | Context / Sample | Resolution in Test Corpus |
|---|---|---|---|---|---|
| 2026-08-02 | Internal Pre-Pilot | FP | `IN_MOBILE` | `Rs. 5000000000` | Ingested into `test_pilot_feedback_1_fp_in_mobile` |
| 2026-08-02 | Internal Pre-Pilot | FN | `PAN` | `ABC PD 5678 K` | Ingested into `test_pilot_feedback_2_fn_pan` |
| 2026-08-02 | Internal Pre-Pilot | FP | `AADHAAR` | `123456789012` | Ingested into `test_pilot_feedback_3_fp_aadhaar` |

---

## 📁 Format & Feature Requirement Findings (Evidence for Phase 3)

| Format / Feature | Requested By | Frequency | Priority for Phase 3 |
|---|---|---|---|
| Excel (.xlsx) | PARTNER_01, PARTNER_03 | High | High (Shipped in Phase 1) |
| CSV (.csv) | PARTNER_02, PARTNER_03 | High | High (Shipped in Phase 1) |
| Word (.docx) | TBD | TBD | Pending Phase 2 Partner Feedback |
| PDF Documents | TBD | TBD | Pending Phase 2 Partner Feedback |
