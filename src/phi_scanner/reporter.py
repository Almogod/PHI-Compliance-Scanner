"""Report generator — CSV, JSON, HTML, and optionally AES-256-GCM encrypted output.

Output format per finding (one row):
  file, sheet, row, column, entity_type, masked_value, confidence

Rollup summary appended at the end of the CSV (as comment rows) and as a
top-level key in the JSON output.

Security note (v3.1):
  The cell-level location data in reports (file + row + column) constitutes a
  precise PII roadmap. An adversary with the report can locate every piece of
  sensitive data without ever reading the original files. For storage at rest
  or distribution to auditors, use write_encrypted() to produce an
  AES-256-GCM encrypted blob that requires a passphrase to open.

  Encryption algorithm: PBKDF2-HMAC-SHA256 (600,000 iterations) → AES-256-GCM
  The resulting .phi file format:
    Header  : b"PHI-SCAN-ENC-v1\n" (16 bytes)
    Salt    : 16 random bytes (for PBKDF2)
    Nonce   : 12 random bytes (for AES-GCM)
    Tag     : 16 bytes (GCM authentication tag, appended after ciphertext)
    Body    : ciphertext (variable length)

No raw PII values are written to the report — only masked representations.
"""
from __future__ import annotations

import csv
import json
import os
from collections import Counter
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

        # Rollup block
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


_ENC_HEADER = b"PHI-SCAN-ENC-v1\n"   # 16-byte magic for format identification
_PBKDF2_ITERATIONS = 600_000         # NIST SP 800-132 recommendation as of 2023


def write_encrypted(
    findings: Sequence[Finding],
    output_path: Path,
    passphrase: str,
) -> None:
    """Write an AES-256-GCM encrypted audit report to output_path.

    The report payload is the same JSON structure as write_json(), but
    wrapped in an authenticated encryption envelope so that:
      - Confidentiality: file-path + cell-location data cannot be read
        without the passphrase.
      - Integrity: the GCM authentication tag detects any tampering.

    Decryption is possible with decrypt_report() below or any AES-GCM
    implementation given the same passphrase and the documented file format.

    Requires: pip install cryptography
    Raises: ImportError with a clear message if cryptography is not installed.
    """
    try:
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
        from cryptography.hazmat.primitives import hashes
    except ImportError as exc:  # pragma: no cover
        raise ImportError(
            "Encrypted output requires the 'cryptography' package.\n"
            "Install it offline: pip install --find-links=wheels cryptography\n"
            f"Original error: {exc}"
        ) from exc

    # Build JSON payload (same as write_json)
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

    # Key derivation
    salt = os.urandom(16)
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,   # 256-bit key
        salt=salt,
        iterations=_PBKDF2_ITERATIONS,
    )
    key = kdf.derive(passphrase.encode("utf-8"))

    # AES-256-GCM encryption
    nonce = os.urandom(12)   # 96-bit nonce for GCM
    aesgcm = AESGCM(key)
    ciphertext_with_tag = aesgcm.encrypt(nonce, plaintext, None)
    # cryptography library appends the 16-byte GCM tag to ciphertext

    # Write: magic header | salt | nonce | ciphertext+tag
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with open(output_path, "wb") as fh:
        fh.write(_ENC_HEADER)
        fh.write(salt)
        fh.write(nonce)
        fh.write(ciphertext_with_tag)


def decrypt_report(encrypted_path: Path, passphrase: str) -> dict:
    """Decrypt a .phi encrypted report and return the JSON payload as a dict.

    Raises:
      ValueError   — if the magic header is wrong (not a PHI encrypted file).
      cryptography.exceptions.InvalidTag — if passphrase is wrong or file is corrupted.
    """
    try:
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
        from cryptography.hazmat.primitives import hashes
    except ImportError as exc:  # pragma: no cover
        raise ImportError(
            "Decryption requires the 'cryptography' package."
        ) from exc

    raw = encrypted_path.read_bytes()
    if not raw.startswith(_ENC_HEADER):
        raise ValueError(
            f"{encrypted_path} does not appear to be a PHI-SCAN encrypted report "
            f"(wrong magic header). Expected: {_ENC_HEADER!r}"
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
    """Write a self-contained executive audit report as an interactive HTML document.

    Zero external network dependencies — 100% offline-ready, suitable for board/auditor presentation.
    """
    counts: Counter[str] = Counter(f.entity_type for f in findings)
    confidence_counts: Counter[str] = Counter(f.confidence for f in findings)
    file_counts: Counter[str] = Counter(f.location.as_dict()["file"] for f in findings)

    total_findings = len(findings)
    high_count = confidence_counts.get("HIGH", 0)
    med_count = confidence_counts.get("MEDIUM", 0)

    if high_count > 0:
        status_badge = '<span class="badge risk-high">CRITICAL RISK — ACTION REQUIRED</span>'
        status_desc = "Verified PII exposures were detected in local files. Immediate remediation recommended."
    elif med_count > 0:
        status_badge = '<span class="badge risk-medium">WARNING — REVIEW REQUIRED</span>'
        status_desc = "Unverified PII candidate patterns were detected. Manual review recommended."
    else:
        status_badge = '<span class="badge risk-low">PASS — LOW RISK</span>'
        status_desc = "No high-confidence PII exposures detected."

    # Build rows HTML
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
            <td>{idx}</td>
            <td class="file-path">{loc['file']}</td>
            <td><span class="location-tag">{loc_display}</span></td>
            <td><span class="entity-tag {entity_class}">{f.entity_type}</span></td>
            <td class="mono">{f.masked_value}</td>
            <td><span class="badge {conf_class}">{f.confidence}</span></td>
        </tr>
        """)

    rows_html = "\n".join(table_rows)

    # Build bar chart items HTML
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
    <style>
        :root {{
            --bg-main: #0f172a;
            --bg-card: #1e293b;
            --bg-hover: #334155;
            --text-main: #f8fafc;
            --text-muted: #94a3b8;
            --border: #334155;
            --primary: #38bdf8;
            --danger: #ef4444;
            --warning: #f59e0b;
            --success: #10b981;
        }}

        * {{ box-sizing: border-box; margin: 0; padding: 0; }}
        body {{
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
            background-color: var(--bg-main);
            color: var(--text-main);
            padding: 2rem;
            line-height: 1.5;
        }}

        .container {{ max-width: 1200px; margin: 0 auto; }}

        header {{
            display: flex;
            justify-content: space-between;
            align-items: flex-start;
            border-bottom: 1px solid var(--border);
            padding-bottom: 1.5rem;
            margin-bottom: 2rem;
        }}

        h1 {{ font-size: 1.875rem; font-weight: 700; color: var(--text-main); }}
        .subtitle {{ color: var(--text-muted); font-size: 0.875rem; margin-top: 0.25rem; }}

        .badge {{
            display: inline-block;
            padding: 0.35rem 0.75rem;
            border-radius: 9999px;
            font-size: 0.75rem;
            font-weight: 700;
            text-transform: uppercase;
            letter-spacing: 0.05em;
        }}
        .risk-high {{ background-color: rgba(239, 68, 68, 0.2); color: var(--danger); border: 1px solid var(--danger); }}
        .risk-medium {{ background-color: rgba(245, 158, 11, 0.2); color: var(--warning); border: 1px solid var(--warning); }}
        .risk-low {{ background-color: rgba(16, 185, 129, 0.2); color: var(--success); border: 1px solid var(--success); }}

        .conf-high {{ background-color: rgba(239, 68, 68, 0.15); color: #fca5a5; }}
        .conf-medium {{ background-color: rgba(245, 158, 11, 0.15); color: #fde047; }}
        .conf-low {{ background-color: rgba(148, 163, 184, 0.15); color: #cbd5e1; }}

        .stats-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
            gap: 1rem;
            margin-bottom: 2rem;
        }}

        .stat-card {{
            background-color: var(--bg-card);
            padding: 1.25rem;
            border-radius: 0.75rem;
            border: 1px solid var(--border);
        }}

        .stat-label {{ color: var(--text-muted); font-size: 0.875rem; font-weight: 500; }}
        .stat-value {{ font-size: 2rem; font-weight: 700; margin-top: 0.25rem; color: var(--text-main); }}

        .section-grid {{
            display: grid;
            grid-template-columns: 2fr 1fr;
            gap: 1.5rem;
            margin-bottom: 2rem;
        }}
        @media (max-width: 900px) {{ .section-grid {{ grid-template-columns: 1fr; }} }}

        .card {{
            background-color: var(--bg-card);
            padding: 1.5rem;
            border-radius: 0.75rem;
            border: 1px solid var(--border);
        }}

        .card-title {{ font-size: 1.125rem; font-weight: 600; margin-bottom: 1rem; border-bottom: 1px solid var(--border); padding-bottom: 0.5rem; }}

        .chart-row {{ display: flex; align-items: center; gap: 0.75rem; margin-bottom: 0.75rem; }}
        .chart-label {{ width: 110px; font-size: 0.875rem; font-weight: 600; color: var(--text-muted); }}
        .chart-bar-bg {{ flex: 1; background-color: var(--bg-main); height: 12px; border-radius: 6px; overflow: hidden; }}
        .chart-bar-fill {{ background: linear-gradient(90deg, #38bdf8, #818cf8); height: 100%; border-radius: 6px; transition: width 0.3s ease; }}
        .chart-val {{ width: 35px; text-align: right; font-weight: 700; font-size: 0.875rem; }}

        .toolbar {{
            display: flex;
            gap: 1rem;
            margin-bottom: 1rem;
            flex-wrap: wrap;
            align-items: center;
        }}
        .search-input {{
            background-color: var(--bg-main);
            border: 1px solid var(--border);
            color: var(--text-main);
            padding: 0.5rem 1rem;
            border-radius: 0.5rem;
            font-size: 0.875rem;
            width: 250px;
        }}
        .filter-btn {{
            background-color: var(--bg-main);
            border: 1px solid var(--border);
            color: var(--text-muted);
            padding: 0.5rem 0.75rem;
            border-radius: 0.5rem;
            font-size: 0.75rem;
            font-weight: 600;
            cursor: pointer;
        }}
        .filter-btn.active {{ background-color: var(--primary); color: #000; border-color: var(--primary); }}

        table {{
            width: 100%;
            border-collapse: collapse;
            font-size: 0.875rem;
        }}
        th, td {{ padding: 0.75rem 1rem; text-align: left; border-bottom: 1px solid var(--border); }}
        th {{ background-color: var(--bg-main); color: var(--text-muted); font-weight: 600; text-transform: uppercase; font-size: 0.75rem; }}
        tr:hover {{ background-color: var(--bg-hover); }}

        .mono {{ font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace; font-weight: 600; color: #a5f3fc; }}
        .file-path {{ word-break: break-all; max-width: 320px; font-size: 0.8125rem; color: #cbd5e1; }}
        .location-tag {{ background: rgba(51, 65, 85, 0.5); padding: 0.2rem 0.4rem; border-radius: 0.25rem; font-size: 0.75rem; }}

        .entity-tag {{ font-weight: 700; font-size: 0.75rem; padding: 0.2rem 0.4rem; border-radius: 0.25rem; }}
        .entity-aadhaar {{ background-color: rgba(56, 189, 248, 0.2); color: #7dd3fc; }}
        .entity-pan {{ background-color: rgba(168, 85, 247, 0.2); color: #c084fc; }}
        .entity-gstin {{ background-color: rgba(236, 72, 153, 0.2); color: #f472b6; }}
        .entity-in_mobile {{ background-color: rgba(52, 211, 153, 0.2); color: #6ee7b7; }}

        footer {{
            margin-top: 3rem;
            padding-top: 1.5rem;
            border-top: 1px solid var(--border);
            color: var(--text-muted);
            font-size: 0.75rem;
            text-align: center;
        }}
    </style>
</head>
<body>
    <div class="container">
        <header>
            <div>
                <h1>PHI Compliance Audit Report</h1>
                <div class="subtitle">Target: {target_path_str or "Local Workspace"} | Generated by PHI Compliance Scanner</div>
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
                <div class="stat-value" style="font-size: 1.25rem; font-weight: 600; margin-top: 0.5rem;">{status_desc}</div>
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

        <footer>
            PHI Compliance Scanner v3.0 — Air-gapped local compliance engine
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

                if (matchesFilter && matchesSearch) {{
                    row.style.display = '';
                }} else {{
                    row.style.display = 'none';
                }}
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

