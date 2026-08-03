"""Report generator — CSV, JSON, HTML, PDF, and AES-256-GCM encrypted output.

Output format per finding (one row):
  file, sheet, row, column, entity_type, masked_value, confidence

Rollup summary appended at the end of the CSV (as comment rows) and as a
top-level key in the JSON output.
"""
from __future__ import annotations

import csv
import json
import os
from collections import Counter
from datetime import datetime
from pathlib import Path
from typing import Sequence

from .engine import Finding

_FIELDNAMES = ["file", "sheet", "row", "column", "entity_type", "masked_value", "confidence"]


def write_csv(findings: Sequence[Finding], output_path: Path) -> None:
    """Write findings to a CSV file, followed by a rollup summary block."""
    counts: Counter[str] = Counter()
    file_counts: Counter[str] = Counter()

    with open(output_path, "w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=_FIELDNAMES)
        writer.writeheader()
        for f in findings:
            row = f.as_dict()
            writer.writerow(row)
            counts[f.entity_type] += 1
            file_counts[f.location.as_dict()["file"]] += 1

        fh.write("\n")
        fh.write("# --- SUMMARY ---\n")
        fh.write(f"# Total findings: {len(findings)}\n")
        for entity, count in sorted(counts.items()):
            fh.write(f"# {entity}: {count}\n")
        fh.write("# Top files by finding count:\n")
        for filepath, count in file_counts.most_common(10):
            fh.write(f"#   {count}  {filepath}\n")


def write_json(findings: Sequence[Finding], output_path: Path) -> None:
    """Write findings and rollup summary to a JSON file."""
    counts: Counter[str] = Counter(f.entity_type for f in findings)
    file_counts: Counter[str] = Counter(
        f.location.as_dict()["file"] for f in findings
    )

    payload = {
        "summary": {
            "total_findings": len(findings),
            "by_entity_type": dict(sorted(counts.items())),
            "top_files": [
                {"file": fp, "count": c}
                for fp, c in file_counts.most_common(10)
            ],
        },
        "findings": [f.as_dict() for f in findings],
    }

    with open(output_path, "w", encoding="utf-8") as fh:
        json.dump(payload, fh, indent=2, ensure_ascii=False)


_ENC_HEADER = b"PHI-SCAN-ENC-v1\n"
_PBKDF2_ITERATIONS = 600_000


def write_encrypted(
    findings: Sequence[Finding],
    output_path: Path,
    passphrase: str,
) -> None:
    """Write an AES-256-GCM encrypted audit report to output_path."""
    try:
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
        from cryptography.hazmat.primitives import hashes
    except ImportError as exc:
        raise ImportError(
            "Encrypted output requires the 'cryptography' package."
        ) from exc

    counts: Counter[str] = Counter(f.entity_type for f in findings)
    file_counts: Counter[str] = Counter(f.location.as_dict()["file"] for f in findings)
    payload = {
        "summary": {
            "total_findings": len(findings),
            "by_entity_type": dict(sorted(counts.items())),
            "top_files": [
                {"file": fp, "count": c}
                for fp, c in file_counts.most_common(10)
            ],
        },
        "findings": [f.as_dict() for f in findings],
    }
    plaintext = json.dumps(payload, indent=2, ensure_ascii=False).encode("utf-8")

    salt = os.urandom(16)
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=_PBKDF2_ITERATIONS,
    )
    key = kdf.derive(passphrase.encode("utf-8"))

    nonce = os.urandom(12)
    aesgcm = AESGCM(key)
    ciphertext_with_tag = aesgcm.encrypt(nonce, plaintext, None)

    output_path.parent.mkdir(parents=True, exist_ok=True)
    with open(output_path, "wb") as fh:
        fh.write(_ENC_HEADER)
        fh.write(salt)
        fh.write(nonce)
        fh.write(ciphertext_with_tag)


def decrypt_report(encrypted_path: Path, passphrase: str) -> dict:
    """Decrypt a .phi encrypted report and return the JSON payload as a dict."""
    try:
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
        from cryptography.hazmat.primitives import hashes
    except ImportError as exc:
        raise ImportError(
            "Decryption requires the 'cryptography' package."
        ) from exc

    raw = encrypted_path.read_bytes()
    if not raw.startswith(_ENC_HEADER):
        raise ValueError(
            f"{encrypted_path} does not appear to be a PHI-SCAN encrypted report."
        )

    offset = len(_ENC_HEADER)
    salt = raw[offset:offset + 16];        offset += 16
    nonce = raw[offset:offset + 12];       offset += 12
    ciphertext_with_tag = raw[offset:]

    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=_PBKDF2_ITERATIONS,
    )
    key = kdf.derive(passphrase.encode("utf-8"))

    aesgcm = AESGCM(key)
    plaintext = aesgcm.decrypt(nonce, ciphertext_with_tag, None)
    return json.loads(plaintext.decode("utf-8"))


def write_html(findings: Sequence[Finding], output_path: Path, target_path_str: str = "") -> None:
    """Write a self-contained executive audit report as an interactive HTML document."""
    counts: Counter[str] = Counter(f.entity_type for f in findings)
    confidence_counts: Counter[str] = Counter(f.confidence for f in findings)
    file_counts: Counter[str] = Counter(f.location.as_dict()["file"] for f in findings)

    total_findings = len(findings)
    high_count = confidence_counts.get("HIGH", 0)
    med_count = confidence_counts.get("MEDIUM", 0)

    if high_count > 0:
        status_badge = '<span class="badge risk-high"><span class="badge-dot"></span>CRITICAL RISK — ACTION REQUIRED</span>'
        status_desc = "Verified PII exposures were detected in local files. Immediate remediation recommended."
    elif med_count > 0:
        status_badge = '<span class="badge risk-medium"><span class="badge-dot"></span>WARNING — REVIEW REQUIRED</span>'
        status_desc = "Unverified PII candidate patterns were detected. Manual review recommended."
    else:
        status_badge = '<span class="badge risk-low"><span class="badge-dot"></span>PASS — LOW RISK</span>'
        status_desc = "No high-confidence PII exposures detected."

    table_rows = []
    for idx, f in enumerate(findings, start=1):
        loc = f.location.as_dict()
        sheet_str = f" ({loc['sheet']})" if loc.get("sheet") else ""
        col_str = f"Col {loc['column']}" if loc.get("column") else ""
        loc_display = f"Row {loc['row']} {col_str}{sheet_str}".strip()

        conf_class = f"conf-{f.confidence.lower()}"
        entity_class = f"entity-{f.entity_type.lower()}"

        table_rows.append(f"""
        <tr data-entity="{f.entity_type}" data-confidence="{f.confidence}">
            <td class="row-num">{idx}</td>
            <td class="file-path">{loc['file']}</td>
            <td><span class="location-tag">{loc_display}</span></td>
            <td><span class="entity-tag {entity_class}">{f.entity_type}</span></td>
            <td class="mono">{f.masked_value}</td>
            <td><span class="badge {conf_class}">{f.confidence}</span></td>
        </tr>
        """)

    rows_html = "\n".join(table_rows)

    chart_items = []
    max_count = max(counts.values()) if counts else 1
    for entity, count in sorted(counts.items()):
        pct = (count / max_count) * 100
        chart_items.append(f"""
        <div class="chart-row">
            <span class="chart-label">{entity}</span>
            <div class="chart-bar-bg">
                <div class="chart-bar-fill" style="width: {pct:.1f}%;"></div>
            </div>
            <span class="chart-val">{count}</span>
        </div>
        """)
    chart_html = "\n".join(chart_items)

    html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>PHI Compliance Audit Report</title>
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&family=JetBrains+Mono:wght@500;600&display=swap" rel="stylesheet">
    <style>
        :root {{
            --ease-out: cubic-bezier(0.23, 1, 0.32, 1);
            --bg-body: #f8fafc;
            --bg-card: #ffffff;
            --bg-subtle: #f1f5f9;
            --bg-hover: #f8fafc;
            --text-main: #0f172a;
            --text-muted: #64748b;
            --text-dim: #94a3b8;
            --border: #e2e8f0;
            --border-hover: #cbd5e1;
            --primary: #4f46e5;
            --primary-light: #e0e7ff;
            --danger: #e11d48;
            --danger-bg: #ffe4e6;
            --warning: #d97706;
            --warning-bg: #fef3c7;
            --success: #059669;
            --success-bg: #d1fae5;
            --shadow-sm: 0 1px 2px 0 rgba(0, 0, 0, 0.03);
            --shadow-md: 0 4px 16px -2px rgba(15, 23, 42, 0.05);
            --shadow-lg: 0 12px 28px -4px rgba(15, 23, 42, 0.08);
            --font-sans: 'Inter', system-ui, -apple-system, sans-serif;
            --font-mono: 'JetBrains Mono', monospace;
        }}
        * {{ box-sizing: border-box; margin: 0; padding: 0; }}
        body {{ font-family: var(--font-sans); background-color: var(--bg-body); color: var(--text-main); padding: 2.5rem 2rem; line-height: 1.5; }}
        .container {{ max-width: 1240px; margin: 0 auto; }}
        header {{ display: flex; justify-content: space-between; align-items: flex-start; border-bottom: 1px solid var(--border); padding-bottom: 1.5rem; margin-bottom: 2rem; }}
        h1 {{ font-size: 1.75rem; font-weight: 700; color: var(--text-main); }}
        .subtitle {{ color: var(--text-muted); font-size: 0.875rem; margin-top: 0.25rem; display: flex; gap: 0.5rem; }}
        .badge {{ display: inline-flex; align-items: center; gap: 0.4rem; padding: 0.4rem 0.85rem; border-radius: 9999px; font-size: 0.75rem; font-weight: 700; text-transform: uppercase; }}
        .badge-dot {{ width: 6px; height: 6px; border-radius: 50%; background-color: currentColor; }}
        .risk-high {{ background-color: var(--danger-bg); color: var(--danger); border: 1px solid rgba(225, 29, 72, 0.2); }}
        .risk-medium {{ background-color: var(--warning-bg); color: var(--warning); border: 1px solid rgba(217, 119, 6, 0.2); }}
        .risk-low {{ background-color: var(--success-bg); color: var(--success); border: 1px solid rgba(5, 150, 105, 0.2); }}
        .conf-high {{ background-color: #ffe4e6; color: #be123c; }}
        .conf-medium {{ background-color: #fef3c7; color: #b45309; }}
        .conf-low {{ background-color: #f1f5f9; color: #475569; }}
        .stats-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(240px, 1fr)); gap: 1.25rem; margin-bottom: 2rem; }}
        .stat-card {{ background-color: var(--bg-card); padding: 1.5rem; border-radius: 0.85rem; border: 1px solid var(--border); box-shadow: var(--shadow-md); }}
        .stat-label {{ color: var(--text-muted); font-size: 0.75rem; font-weight: 600; text-transform: uppercase; }}
        .stat-value {{ font-size: 2.25rem; font-weight: 800; margin-top: 0.35rem; color: var(--text-main); font-family: var(--font-mono); }}
        .section-grid {{ display: grid; grid-template-columns: 1.8fr 1.2fr; gap: 1.5rem; margin-bottom: 2rem; }}
        .card {{ background-color: var(--bg-card); padding: 1.75rem; border-radius: 0.85rem; border: 1px solid var(--border); box-shadow: var(--shadow-md); }}
        .card-title {{ font-size: 1rem; font-weight: 700; color: var(--text-main); margin-bottom: 1.25rem; border-bottom: 1px solid var(--border); padding-bottom: 0.75rem; }}
        .chart-row {{ display: flex; align-items: center; gap: 1rem; margin-bottom: 0.85rem; }}
        .chart-label {{ width: 110px; font-size: 0.8125rem; font-weight: 600; color: var(--text-muted); }}
        .chart-bar-bg {{ flex: 1; background-color: var(--bg-subtle); height: 10px; border-radius: 9999px; overflow: hidden; }}
        .chart-bar-fill {{ background: linear-gradient(90deg, #6366f1, #3b82f6); height: 100%; border-radius: 9999px; }}
        .chart-val {{ width: 40px; text-align: right; font-weight: 700; font-size: 0.8125rem; color: var(--text-main); font-family: var(--font-mono); }}
        .toolbar {{ display: flex; gap: 0.75rem; margin-bottom: 1.25rem; flex-wrap: wrap; }}
        .search-input {{ background-color: var(--bg-card); border: 1px solid var(--border); padding: 0.55rem 1rem; border-radius: 0.6rem; font-size: 0.875rem; width: 280px; }}
        .filter-btn {{ background-color: var(--bg-subtle); border: 1px solid var(--border); color: var(--text-muted); padding: 0.5rem 0.85rem; border-radius: 0.6rem; font-size: 0.75rem; font-weight: 600; cursor: pointer; }}
        .filter-btn.active {{ background-color: var(--primary); color: #ffffff; border-color: var(--primary); }}
        .table-wrapper {{ overflow-x: auto; border-radius: 0.6rem; border: 1px solid var(--border); }}
        table {{ width: 100%; border-collapse: collapse; font-size: 0.875rem; background-color: var(--bg-card); }}
        th, td {{ padding: 0.85rem 1.1rem; text-align: left; border-bottom: 1px solid var(--border); }}
        th {{ background-color: var(--bg-subtle); color: var(--text-muted); font-weight: 600; text-transform: uppercase; font-size: 0.725rem; }}
        .mono {{ font-family: var(--font-mono); font-weight: 600; color: #0284c7; background: #f0f9ff; padding: 0.2rem 0.5rem; border-radius: 0.35rem; border: 1px solid #bae6fd; font-size: 0.8125rem; }}
        .file-path {{ word-break: break-all; max-width: 320px; font-size: 0.8125rem; font-weight: 500; }}
        .location-tag {{ background: var(--bg-subtle); color: var(--text-muted); padding: 0.25rem 0.5rem; border-radius: 0.35rem; font-size: 0.75rem; border: 1px solid var(--border); }}
        .entity-tag {{ font-weight: 700; font-size: 0.725rem; padding: 0.25rem 0.5rem; border-radius: 0.35rem; display: inline-block; }}
        .entity-aadhaar {{ background-color: #e0f2fe; color: #0369a1; border: 1px solid #bae6fd; }}
        .entity-pan {{ background-color: #f3e8ff; color: #7e22ce; border: 1px solid #e9d5ff; }}
        .entity-gstin {{ background-color: #fce7f3; color: #be185d; border: 1px solid #fbcfe8; }}
        .entity-in_mobile {{ background-color: #d1fae5; color: #047857; border: 1px solid #a7f3d0; }}
        footer {{ margin-top: 3rem; padding-top: 1.5rem; border-top: 1px solid var(--border); color: var(--text-muted); font-size: 0.8125rem; text-align: center; }}
    </style>
</head>
<body>
    <div class="container">
        <header>
            <div>
                <h1>PHI Compliance Audit Report</h1>
                <div class="subtitle">
                    <span>Target: {target_path_str or "Local Workspace"}</span>
                    <span>•</span>
                    <span>Generated by PHI Compliance Scanner</span>
                </div>
            </div>
            <div>
                {status_badge}
            </div>
        </header>

        <div class="stats-grid">
            <div class="stat-card">
                <div class="stat-label">Total Findings</div>
                <div class="stat-value">{total_findings}</div>
            </div>
            <div class="stat-card">
                <div class="stat-label">High Confidence</div>
                <div class="stat-value" style="color: var(--danger);">{high_count}</div>
            </div>
            <div class="stat-card">
                <div class="stat-label">Affected Files</div>
                <div class="stat-value">{len(file_counts)}</div>
            </div>
            <div class="stat-card">
                <div class="stat-label">Audit Status</div>
                <div class="stat-value" style="font-size: 1.15rem; font-weight: 600; margin-top: 0.5rem;">{status_desc}</div>
            </div>
        </div>

        <div class="section-grid">
            <div class="card">
                <div class="card-title">Finding Distribution by Entity Type</div>
                {chart_html}
            </div>
            <div class="card">
                <div class="card-title">Compliance Assurance</div>
                <p style="font-size: 0.875rem; color: var(--text-muted); line-height: 1.6;">
                    🔒 <strong>Zero PII Persistence Guarantee:</strong><br>
                    This audit report contains only masked representation strings (e.g., <code>XXXX XXXX 1234</code>).
                    No plain-text Aadhaar, PAN, GSTIN, or phone numbers were written to disk or transmitted off this device.
                </p>
            </div>
        </div>

        <div class="card">
            <div class="card-title">Detailed Audit Trail</div>
            <div class="toolbar">
                <input type="text" id="searchInput" class="search-input" placeholder="Search files or values...">
                <button class="filter-btn active" onclick="filterEntity('ALL')">All Types</button>
                <button class="filter-btn" onclick="filterEntity('AADHAAR')">Aadhaar</button>
                <button class="filter-btn" onclick="filterEntity('PAN')">PAN</button>
                <button class="filter-btn" onclick="filterEntity('GSTIN')">GSTIN</button>
                <button class="filter-btn" onclick="filterEntity('IN_MOBILE')">Mobile</button>
            </div>

            <div class="table-wrapper">
                <table>
                    <thead>
                        <tr>
                            <th>#</th>
                            <th>File Location</th>
                            <th>Position</th>
                            <th>Entity Type</th>
                            <th>Masked Value</th>
                            <th>Confidence</th>
                        </tr>
                    </thead>
                    <tbody id="findingsBody">
                        {rows_html}
                    </tbody>
                </table>
            </div>
        </div>

        <footer>
            PHI Compliance Scanner v4.0 — Air-gapped local compliance engine
        </footer>
    </div>

    <script>
        let currentFilter = 'ALL';
        const searchInput = document.getElementById('searchInput');
        const rows = document.querySelectorAll('#findingsBody tr');

        function applyFilters() {{
            const searchVal = searchInput.value.toLowerCase();
            rows.forEach(row => {{
                const entity = row.getAttribute('data-entity');
                const text = row.innerText.toLowerCase();
                const matchesFilter = (currentFilter === 'ALL' || entity === currentFilter);
                const matchesSearch = text.includes(searchVal);
                row.style.display = (matchesFilter && matchesSearch) ? '' : 'none';
            }});
        }}

        function filterEntity(entity) {{
            currentFilter = entity;
            document.querySelectorAll('.filter-btn').forEach(btn => {{
                btn.classList.remove('active');
                if (btn.innerText.toUpperCase().includes(entity) || (entity === 'ALL' && btn.innerText === 'All Types')) {{
                    btn.classList.add('active');
                }}
            }});
            applyFilters();
        }}

        searchInput.addEventListener('input', applyFilters);
    </script>
</body>
</html>
"""

    with open(output_path, "w", encoding="utf-8") as fh:
        fh.write(html_content)


def write_pdf_summary(findings: Sequence[Finding], output_path: Path, target_path_str: str = "") -> None:
    """Generate an executive-facing PDF compliance summary report."""
    counts: Counter[str] = Counter(f.entity_type for f in findings)
    confidence_counts: Counter[str] = Counter(f.confidence for f in findings)
    file_counts: Counter[str] = Counter(f.location.as_dict()["file"] for f in findings)

    total_findings = len(findings)
    high_count = confidence_counts.get("HIGH", 0)

    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    risk_level = "CRITICAL RISK" if high_count > 0 else ("WARNING" if len(findings) > 0 else "LOW RISK")

    try:
        from reportlab.lib.pagesizes import letter
        from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
        from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
        from reportlab.lib import colors

        doc = SimpleDocTemplate(str(output_path), pagesize=letter)
        styles = getSampleStyleSheet()
        story = []

        title_style = ParagraphStyle("TitleStyle", parent=styles["Heading1"], fontSize=20, leading=24, textColor=colors.HexColor("#0f172a"))
        sub_style = ParagraphStyle("SubStyle", parent=styles["Normal"], fontSize=10, textColor=colors.HexColor("#64748b"))

        story.append(Paragraph("PHI & PII Compliance Executive Summary", title_style))
        story.append(Paragraph(f"Target: {target_path_str or 'Local Workspace'} | Generated: {timestamp}", sub_style))
        story.append(Spacer(1, 15))

        # Risk Banner
        banner_color = colors.HexColor("#e11d48") if high_count > 0 else colors.HexColor("#059669")
        banner_text = f"Audit Status: <b>{risk_level}</b> ({total_findings} total findings, {high_count} high-confidence exposures)"
        banner_style = ParagraphStyle("BannerStyle", parent=styles["Normal"], fontSize=11, textColor=colors.white)
        
        banner_table = Table([[Paragraph(banner_text, banner_style)]], colWidths=[540])
        banner_table.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (-1,-1), banner_color),
            ('PADDING', (0,0), (-1,-1), 10),
            ('CORNER_PAD', (0,0), (-1,-1), 4),
        ]))
        story.append(banner_table)
        story.append(Spacer(1, 20))

        # Summary Metrics Table
        summary_data = [
            ["Entity Type", "Finding Count", "Risk Level"],
        ]
        for entity, count in sorted(counts.items()):
            summary_data.append([entity, str(count), "HIGH" if entity in ("AADHAAR", "PAN", "BANK_ACCOUNT") else "MEDIUM"])

        t = Table(summary_data, colWidths=[200, 170, 170])
        t.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (-1,0), colors.HexColor("#f1f5f9")),
            ('TEXTCOLOR', (0,0), (-1,0), colors.HexColor("#0f172a")),
            ('FONTNAME', (0,0), (-1,0), 'Helvetica-Bold'),
            ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor("#e2e8f0")),
            ('PADDING', (0,0), (-1,-1), 8),
        ]))
        story.append(t)
        doc.build(story)

    except ImportError:
        # Fallback to structured plain-text PDF content writer when reportlab is not installed
        pdf_lines = [
            "%PDF-1.4",
            "1 0 obj << /Type /Catalog /Pages 2 0 R >> endobj",
            "2 0 obj << /Type /Pages /Kids [3 0 R] /Count 1 >> endobj",
            "3 0 obj << /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Contents 4 0 R /Resources << /Font << /F1 5 0 R >> >> >> endobj",
            "5 0 obj << /Type /Font /Subtype /Type1 /BaseFont /Helvetica >> endobj",
        ]
        body_text = (
            f"PHI & PII Compliance Executive Summary\\n"
            f"Target: {target_path_str or 'Local Workspace'} | Generated: {timestamp}\\n"
            f"Status: {risk_level} | Total Findings: {total_findings} | High Confidence: {high_count}\\n"
            f"Affected Files: {len(file_counts)}\\n\\n"
            f"Entity Distribution:\\n"
        )
        for entity, count in sorted(counts.items()):
            body_text += f" - {entity}: {count}\\n"

        content_stream = f"BT /F1 12 Tf 50 720 Td ({body_text}) Tj ET"
        pdf_lines.extend([
            f"4 0 obj << /Length {len(content_stream)} >> stream",
            content_stream,
            "endstream endobj",
            "xref",
            "0 6",
            "0000000000 65535 f ",
            "0000000009 00000 n ",
            "0000000058 00000 n ",
            "0000000115 00000 n ",
            "0000000280 00000 n ",
            "0000000200 00000 n ",
            "trailer << /Size 6 /Root 1 0 R >>",
            "startxref",
            "400",
            "%%EOF",
        ])
        output_path.parent.mkdir(parents=True, exist_ok=True)
        with open(output_path, "wb") as f:
            f.write("\n".join(pdf_lines).encode("latin1"))
