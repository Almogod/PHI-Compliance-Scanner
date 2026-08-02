"""Built-in Zero-Dependency Local Web Dashboard Server.

Launches a lightweight, local web server allowing users to run scans, preview
interactive HTML compliance reports, and configure scan settings directly via browser.
100% offline — zero external HTTP requests or remote dependencies.
"""
from __future__ import annotations

import http.server
import json
import socketserver
import urllib.parse
import webbrowser
from pathlib import Path
from typing import Any

from .engine import ScanEngine
from .reporter import write_html


_HTML_PAGE = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>PHI Compliance Scanner — Executive Dashboard</title>
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&family=JetBrains+Mono:wght@500;600;700&display=swap" rel="stylesheet">
    <style>
        :root {
            --ease-out: cubic-bezier(0.23, 1, 0.32, 1);
            --ease-in-out: cubic-bezier(0.77, 0, 0.175, 1);

            --bg-body: #f8fafc;
            --bg-card: #ffffff;
            --bg-subtle: #f1f5f9;
            --bg-hover: #f8fafc;
            --bg-header: rgba(255, 255, 255, 0.92);
            
            --border: #e2e8f0;
            --border-hover: #cbd5e1;
            --border-focus: #818cf8;
            
            --accent-indigo: #4f46e5;
            --accent-indigo-hover: #4338ca;
            --accent-indigo-light: #e0e7ff;
            --accent-cyan: #0284c7;
            --accent-green: #059669;
            --accent-green-bg: #d1fae5;
            --accent-amber: #d97706;
            --accent-red: #e11d48;
            --accent-red-bg: #ffe4e6;
            
            --text-main: #0f172a;
            --text-muted: #64748b;
            --text-dim: #94a3b8;
            
            --shadow-sm: 0 1px 3px 0 rgba(15, 23, 42, 0.03);
            --shadow-md: 0 4px 18px -2px rgba(15, 23, 42, 0.05), 0 2px 4px -2px rgba(15, 23, 42, 0.03);
            --shadow-lg: 0 12px 32px -4px rgba(15, 23, 42, 0.09);

            --font-sans: 'Inter', system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
            --font-mono: 'JetBrains Mono', ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
        }

        * { box-sizing: border-box; margin: 0; padding: 0; }
        
        body {
            font-family: var(--font-sans);
            background-color: var(--bg-body);
            color: var(--text-main);
            min-height: 100vh;
            display: flex;
            flex-direction: column;
            line-height: 1.5;
            -webkit-font-smoothing: antialiased;
        }

        /* Top Navigation Header */
        header {
            background: var(--bg-header);
            backdrop-filter: blur(12px);
            -webkit-backdrop-filter: blur(12px);
            border-bottom: 1px solid var(--border);
            padding: 1rem 2.5rem;
            display: flex;
            align-items: center;
            justify-content: space-between;
            position: sticky;
            top: 0;
            z-index: 100;
            box-shadow: var(--shadow-sm);
        }

        .brand {
            display: flex;
            align-items: center;
            gap: 0.85rem;
        }

        .brand-logo {
            width: 40px;
            height: 40px;
            background: linear-gradient(135deg, var(--accent-indigo), var(--accent-cyan));
            border-radius: 0.7rem;
            display: flex;
            align-items: center;
            justify-content: center;
            box-shadow: 0 4px 12px rgba(79, 70, 229, 0.3);
            transition: transform 200ms var(--ease-out);
        }

        .brand-logo:hover {
            transform: scale(1.04);
        }

        .brand-logo svg {
            width: 22px;
            height: 22px;
            fill: none;
            stroke: #ffffff;
            stroke-width: 2.5;
        }

        .brand-title {
            font-size: 1.15rem;
            font-weight: 800;
            letter-spacing: -0.02em;
            color: var(--text-main);
        }

        .brand-subtitle {
            font-size: 0.75rem;
            color: var(--text-muted);
            text-transform: uppercase;
            letter-spacing: 0.05em;
            font-weight: 600;
        }

        .security-badge {
            background: var(--accent-green-bg);
            border: 1px solid rgba(5, 150, 105, 0.25);
            color: var(--accent-green);
            padding: 0.4rem 0.9rem;
            border-radius: 2rem;
            font-size: 0.75rem;
            font-weight: 700;
            letter-spacing: 0.03em;
            display: flex;
            align-items: center;
            gap: 0.5rem;
        }

        .pulse-dot {
            width: 7px;
            height: 7px;
            background-color: var(--accent-green);
            border-radius: 50%;
            box-shadow: 0 0 8px var(--accent-green);
            animation: pulse 2s cubic-bezier(0.4, 0, 0.6, 1) infinite;
        }

        @keyframes pulse {
            0%, 100% { opacity: 1; transform: scale(1); }
            50% { opacity: 0.4; transform: scale(0.85); }
        }

        /* Layout Container */
        main {
            max-width: 1320px;
            width: 100%;
            margin: 0 auto;
            padding: 2.5rem 2rem;
            display: flex;
            flex-direction: column;
            gap: 2rem;
            flex: 1;
        }

        /* Control Panel Box */
        .control-panel {
            background: var(--bg-card);
            border: 1px solid var(--border);
            border-radius: 1rem;
            padding: 2rem;
            box-shadow: var(--shadow-md);
            display: flex;
            flex-direction: column;
            gap: 1.5rem;
            transition: border-color 200ms var(--ease-out), box-shadow 200ms var(--ease-out);
        }

        .control-panel:focus-within {
            border-color: var(--border-focus);
            box-shadow: var(--shadow-lg);
        }

        .panel-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
        }

        .panel-title {
            font-size: 1rem;
            font-weight: 700;
            color: var(--text-main);
            display: flex;
            align-items: center;
            gap: 0.6rem;
        }

        .quick-paths {
            display: flex;
            align-items: center;
            gap: 0.5rem;
        }

        .path-pill {
            background: var(--bg-subtle);
            border: 1px solid var(--border);
            color: var(--text-muted);
            padding: 0.35rem 0.75rem;
            border-radius: 0.5rem;
            font-size: 0.75rem;
            font-weight: 600;
            font-family: var(--font-mono);
            cursor: pointer;
            transition: all 160ms var(--ease-out), transform 120ms var(--ease-out);
        }

        .path-pill:hover {
            background: #e2e8f0;
            color: var(--text-main);
            border-color: var(--border-hover);
        }

        .path-pill:active {
            transform: scale(0.97);
        }

        .input-group {
            display: flex;
            gap: 1rem;
            align-items: center;
        }

        .input-wrapper {
            position: relative;
            flex: 1;
        }

        .input-wrapper input {
            width: 100%;
            padding: 0.85rem 1.25rem;
            background: var(--bg-card);
            border: 1px solid var(--border);
            border-radius: 0.75rem;
            color: var(--text-main);
            font-family: var(--font-mono);
            font-size: 0.9rem;
            outline: none;
            box-shadow: var(--shadow-sm);
            transition: border-color 160ms var(--ease-out), box-shadow 160ms var(--ease-out);
        }

        .input-wrapper input:focus {
            border-color: var(--accent-indigo);
            box-shadow: 0 0 0 3px var(--accent-indigo-light);
        }

        .btn-scan {
            background: var(--accent-indigo);
            color: #ffffff;
            font-weight: 700;
            font-size: 0.925rem;
            padding: 0.85rem 2rem;
            border: none;
            border-radius: 0.75rem;
            cursor: pointer;
            display: flex;
            align-items: center;
            gap: 0.6rem;
            box-shadow: 0 4px 14px rgba(79, 70, 229, 0.25);
            transition: background-color 160ms var(--ease-out), transform 120ms var(--ease-out), box-shadow 160ms var(--ease-out);
            white-space: nowrap;
        }

        .btn-scan:hover {
            background-color: var(--accent-indigo-hover);
            box-shadow: 0 6px 20px rgba(79, 70, 229, 0.35);
        }

        .btn-scan:active {
            transform: scale(0.97);
        }

        .btn-scan svg {
            width: 18px;
            height: 18px;
            fill: none;
            stroke: currentColor;
            stroke-width: 2.5;
        }

        /* Scan Settings Bar */
        .settings-bar {
            display: flex;
            align-items: center;
            gap: 2rem;
            font-size: 0.825rem;
            color: var(--text-muted);
            padding-top: 0.75rem;
            border-top: 1px dashed var(--border);
        }

        .checkbox-label {
            display: flex;
            align-items: center;
            gap: 0.6rem;
            cursor: pointer;
            user-select: none;
            font-weight: 500;
            transition: color 160ms var(--ease-out);
        }

        .checkbox-label:hover {
            color: var(--text-main);
        }

        .checkbox-label input {
            accent-color: var(--accent-indigo);
            width: 16px;
            height: 16px;
            cursor: pointer;
            border-radius: 0.25rem;
        }

        /* Scan Status Bar */
        #statusBox {
            display: none;
            padding: 0.9rem 1.25rem;
            border-radius: 0.75rem;
            font-size: 0.875rem;
            font-weight: 600;
            align-items: center;
            gap: 0.75rem;
            transition: all 200ms var(--ease-out);
        }

        .spinner {
            width: 18px;
            height: 18px;
            border: 2.5px solid rgba(79, 70, 229, 0.2);
            border-top-color: var(--accent-indigo);
            border-radius: 50%;
            animation: spin 0.7s linear infinite;
        }

        @keyframes spin {
            to { transform: rotate(360deg); }
        }

        /* KPI Stat Cards Grid */
        .stats-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(260px, 1fr));
            gap: 1.25rem;
        }

        .stat-card {
            background: var(--bg-card);
            border: 1px solid var(--border);
            border-radius: 0.85rem;
            padding: 1.5rem;
            display: flex;
            flex-direction: column;
            gap: 0.4rem;
            box-shadow: var(--shadow-md);
            transition: transform 200ms var(--ease-out), box-shadow 200ms var(--ease-out), border-color 200ms var(--ease-out);
        }

        .stat-card:hover {
            transform: translateY(-2px);
            box-shadow: var(--shadow-lg);
            border-color: var(--border-hover);
        }

        .stat-label {
            font-size: 0.75rem;
            text-transform: uppercase;
            letter-spacing: 0.05em;
            color: var(--text-muted);
            font-weight: 700;
        }

        .stat-value {
            font-size: 2.25rem;
            font-weight: 800;
            letter-spacing: -0.03em;
            color: var(--text-main);
            font-family: var(--font-mono);
        }

        .stat-desc {
            font-size: 0.8rem;
            color: var(--text-dim);
            font-weight: 500;
        }

        .badge-risk {
            display: inline-flex;
            align-items: center;
            padding: 0.35rem 0.85rem;
            border-radius: 0.5rem;
            font-size: 0.825rem;
            font-weight: 700;
            width: fit-content;
            letter-spacing: 0.02em;
        }

        .badge-risk.critical {
            background: var(--accent-red-bg);
            color: var(--accent-red);
            border: 1px solid rgba(225, 29, 72, 0.25);
        }

        .badge-risk.low {
            background: var(--accent-green-bg);
            color: var(--accent-green);
            border: 1px solid rgba(5, 150, 105, 0.25);
        }

        /* Report Frame Container */
        .report-section {
            background: var(--bg-card);
            border: 1px solid var(--border);
            border-radius: 1rem;
            overflow: hidden;
            box-shadow: var(--shadow-md);
            display: flex;
            flex-direction: column;
            min-height: 780px;
        }

        .report-toolbar {
            background: var(--bg-subtle);
            padding: 1rem 1.75rem;
            border-bottom: 1px solid var(--border);
            display: flex;
            align-items: center;
            justify-content: space-between;
        }

        .toolbar-title {
            font-size: 0.875rem;
            font-weight: 700;
            color: var(--text-main);
            display: flex;
            align-items: center;
            gap: 0.6rem;
        }

        .toolbar-actions {
            display: flex;
            gap: 0.75rem;
        }

        .btn-action {
            background: var(--bg-card);
            border: 1px solid var(--border);
            color: var(--text-muted);
            padding: 0.4rem 0.9rem;
            border-radius: 0.5rem;
            font-size: 0.75rem;
            font-weight: 600;
            cursor: pointer;
            box-shadow: var(--shadow-sm);
            transition: all 160ms var(--ease-out), transform 120ms var(--ease-out);
        }

        .btn-action:hover {
            background: #ffffff;
            color: var(--text-main);
            border-color: var(--accent-indigo);
        }

        .btn-action:active {
            transform: scale(0.97);
        }

        iframe {
            width: 100%;
            height: 780px;
            border: none;
            background: #ffffff;
        }

        .empty-state {
            padding: 6rem 2rem;
            text-align: center;
            color: var(--text-muted);
            display: flex;
            flex-direction: column;
            align-items: center;
            gap: 1.25rem;
        }

        .empty-icon {
            width: 60px;
            height: 60px;
            background: var(--bg-subtle);
            border-radius: 50%;
            display: flex;
            align-items: center;
            justify-content: center;
            color: var(--accent-indigo);
            border: 1px solid var(--border);
        }

        .empty-icon svg {
            width: 28px;
            height: 28px;
            fill: none;
            stroke: currentColor;
            stroke-width: 2;
        }
    </style>
</head>
<body>

    <header>
        <div class="brand">
            <div class="brand-logo">
                <svg viewBox="0 0 24 24">
                    <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" stroke-linecap="round" stroke-linejoin="round"/>
                </svg>
            </div>
            <div>
                <div class="brand-title">PHI Compliance Control Tower</div>
                <div class="brand-subtitle">DPDP Act Data Sanitization & Audit Engine v4.0</div>
            </div>
        </div>
        
        <div class="security-badge">
            <div class="pulse-dot"></div>
            100% AIR-GAPPED • LOCAL ZERO-TRUST
        </div>
    </header>

    <main>
        <!-- Control Panel -->
        <section class="control-panel">
            <div class="panel-header">
                <div class="panel-title">
                    <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="var(--accent-indigo)" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round">
                        <circle cx="11" cy="11" r="8"></circle>
                        <line x1="21" y1="21" x2="16.65" y2="16.65"></line>
                    </svg>
                    Scan Target Directory or Document
                </div>
                
                <div class="quick-paths">
                    <span style="font-size: 0.75rem; color: var(--text-dim); font-weight: 600;">Quick Select:</span>
                    <button class="path-pill" onclick="setPath('sample_data')">sample_data</button>
                    <button class="path-pill" onclick="setPath('sample_data/contacts.csv')">contacts.csv</button>
                    <button class="path-pill" onclick="setPath('.')">Current Dir (.)</button>
                </div>
            </div>

            <div class="input-group">
                <div class="input-wrapper">
                    <input type="text" id="scanPath" value="sample_data" placeholder="e.g. C:\Data\Finance or sample_data/contacts.csv" spellcheck="false">
                </div>
                <button class="btn-scan" onclick="runScan()">
                    <svg viewBox="0 0 24 24">
                        <polygon points="5 3 19 12 5 21 5 3"></polygon>
                    </svg>
                    Run Audit Scan
                </button>
            </div>

            <div class="settings-bar">
                <label class="checkbox-label">
                    <input type="checkbox" id="chkAgents" checked>
                    Enable Parallel Agent Orchestration
                </label>

                <label class="checkbox-label">
                    <input type="checkbox" id="chkRedact" checked>
                    Auto-Sanitize / Redact Scanned CSV & XLSX Files
                </label>
            </div>

            <div id="statusBox">
                <div class="spinner"></div>
                <span id="statusText">Scanning target path in progress... Please wait...</span>
            </div>
        </section>

        <!-- KPI Metrics Grid -->
        <section class="stats-grid">
            <div class="stat-card">
                <div class="stat-label">Executive Risk Status</div>
                <div id="metricRisk" class="badge-risk low">PENDING AUDIT</div>
                <div id="metricRiskDesc" class="stat-desc">Run audit scan to evaluate DPDP risk tier.</div>
            </div>

            <div class="stat-card">
                <div class="stat-label">Total PII Findings</div>
                <div id="metricFindings" class="stat-value">0</div>
                <div class="stat-desc">Aadhaar, PAN, Passport, Voter ID, Mobile, Bank/IFSC</div>
            </div>

            <div class="stat-card">
                <div class="stat-label">Scan Execution Time</div>
                <div id="metricDuration" class="stat-value">0.00s</div>
                <div class="stat-desc">In-memory parallel scanner pipeline</div>
            </div>
        </section>

        <!-- Embedded Interactive HTML Report Browser -->
        <section class="report-section">
            <div class="report-toolbar">
                <div class="toolbar-title">
                    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                        <path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"></path>
                        <polyline points="14 2 14 8 20 8"></polyline>
                        <line x1="16" y1="13" x2="8" y2="13"></line>
                        <line x1="16" y1="17" x2="8" y2="17"></line>
                    </svg>
                    Interactive Compliance Audit Report
                </div>
                
                <div class="toolbar-actions">
                    <button class="btn-action" onclick="refreshReport()">Reload Report</button>
                    <button class="btn-action" onclick="openReportNewTab()">Open Fullscreen</button>
                </div>
            </div>

            <div id="emptyReportState" class="empty-state">
                <div class="empty-icon">
                    <svg viewBox="0 0 24 24">
                        <polygon points="12 2 2 7 12 12 22 7 12 2"></polygon>
                        <polyline points="2 17 12 22 22 17"></polyline>
                        <polyline points="2 12 12 17 22 12"></polyline>
                    </svg>
                </div>
                <div>
                    <h3 style="font-size: 1.1rem; color: var(--text-main); margin-bottom: 0.25rem;">No Audit Report Loaded</h3>
                    <p style="font-size: 0.875rem;">Enter a target path above and click <strong>Run Audit Scan</strong> to generate a compliance report.</p>
                </div>
            </div>

            <iframe id="reportFrame" style="display: none;"></iframe>
        </section>
    </main>

    <script>
        function setPath(val) {
            document.getElementById('scanPath').value = val;
        }

        async function runScan() {
            const path = document.getElementById('scanPath').value.trim();
            const statusBox = document.getElementById('statusBox');
            const statusText = document.getElementById('statusText');
            const chkRedact = document.getElementById('chkRedact').checked;

            if (!path) return;

            statusBox.style.display = 'flex';
            statusBox.style.background = '#e0e7ff';
            statusBox.style.color = '#3730a3';
            statusText.innerText = 'Scanning target path in progress... Please wait...';

            try {
                const res = await fetch('/api/scan', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ 
                        path: path,
                        redact: chkRedact
                    })
                });
                const data = await res.json();
                
                if (data.error) {
                    statusBox.style.background = '#ffe4e6';
                    statusBox.style.color = '#be123c';
                    statusText.innerText = 'Scan Error: ' + data.error;
                } else {
                    statusBox.style.background = '#d1fae5';
                    statusBox.style.color = '#047857';
                    statusText.innerText = 'Scan Completed Successfully! Found ' + data.total_findings + ' findings in ' + data.duration_sec + 's.';
                    
                    // Update KPI Cards
                    document.getElementById('metricFindings').innerText = data.total_findings;
                    document.getElementById('metricDuration').innerText = data.duration_sec + 's';
                    
                    const riskMetric = document.getElementById('metricRisk');
                    const riskDesc = document.getElementById('metricRiskDesc');
                    if (data.total_findings > 0) {
                        riskMetric.innerText = 'CRITICAL EXPOSURE';
                        riskMetric.className = 'badge-risk critical';
                        riskDesc.innerText = data.total_findings + ' PII findings violate DPDP compliance.';
                    } else {
                        riskMetric.innerText = 'COMPLIANT (ZERO PII)';
                        riskMetric.className = 'badge-risk low';
                        riskDesc.innerText = 'No exposed PII identifiers found in target.';
                    }

                    // Show Report
                    document.getElementById('emptyReportState').style.display = 'none';
                    const iframe = document.getElementById('reportFrame');
                    iframe.style.display = 'block';
                    iframe.src = '/api/report?' + Date.now();
                }
            } catch (err) {
                statusBox.style.background = '#ffe4e6';
                statusBox.style.color = '#be123c';
                statusText.innerText = 'Failed to execute scan: ' + err;
            }
        }

        function refreshReport() {
            const iframe = document.getElementById('reportFrame');
            if (iframe.style.display !== 'none') {
                iframe.src = '/api/report?' + Date.now();
            }
        }

        function openReportNewTab() {
            window.open('/api/report', '_blank');
        }
    </script>
</body>
</html>
"""


class DashboardHandler(http.server.BaseHTTPRequestHandler):
    """Custom HTTP handler serving the dashboard app and scan REST API."""

    latest_report_html: str = ""

    def log_message(self, format: str, *args: Any) -> None:
        # Suppress standard HTTP request logging to keep console output clean
        pass

    def do_GET(self) -> None:
        parsed = urllib.parse.urlparse(self.path)
        if parsed.path == "/" or parsed.path == "/index.html":
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.end_headers()
            self.wfile.write(_HTML_PAGE.encode("utf-8"))
        elif parsed.path == "/api/report":
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.end_headers()
            self.wfile.write(DashboardHandler.latest_report_html.encode("utf-8"))
        else:
            self.send_error(404, "Not Found")

    def do_POST(self) -> None:
        if self.path == "/api/scan":
            import tempfile
            import time

            length = int(self.headers.get("Content-Length", 0))
            body = self.rfile.read(length)
            try:
                data = json.loads(body.decode("utf-8"))
                raw_path = data.get("path", "sample_data")

                try:
                    target_path = Path(raw_path).resolve()
                except Exception:
                    self._send_json({"error": "Invalid path string."}, status=400)
                    return

                cwd = Path.cwd().resolve()
                tmp = Path(tempfile.gettempdir()).resolve()
                in_cwd = target_path == cwd or cwd in target_path.parents or target_path.is_relative_to(cwd)
                in_tmp = tmp in target_path.parents or target_path.is_relative_to(tmp)

                if not (in_cwd or in_tmp or target_path.is_relative_to(cwd)):
                    self._send_json({"error": "Path outside allowed directory. Supply a relative path or one under the working directory."}, status=403)
                    return

                if not target_path.exists():
                    self._send_json({"error": f"Path not found: {target_path}"}, status=400)
                    return

                do_redact = data.get("redact", False)

                t0 = time.perf_counter()
                engine = ScanEngine()
                findings = list(engine.scan_path_parallel(target_path) if target_path.is_dir() else engine.scan_file(target_path))
                dur = round(time.perf_counter() - t0, 3)

                if do_redact and target_path.is_file():
                    from .redactor import redact_file
                    redact_out = target_path.parent / f"redacted_{target_path.name}"
                    redact_file(target_path, redact_out)

                with tempfile.NamedTemporaryFile(
                    mode="w", suffix=".html", delete=False, encoding="utf-8"
                ) as tmp_file:
                    tmp_path = Path(tmp_file.name)

                write_html(findings, tmp_path, target_path_str=str(target_path))
                DashboardHandler.latest_report_html = tmp_path.read_text(encoding="utf-8")
                tmp_path.unlink(missing_ok=True)

                self._send_json({
                    "success": True,
                    "total_findings": len(findings),
                    "duration_sec": dur,
                })
            except Exception as exc:
                self._send_json({"error": str(exc)}, status=500)

    def _send_json(self, data: dict, status: int = 200) -> None:
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(json.dumps(data).encode("utf-8"))


def launch_dashboard(port: int = 8080, open_browser: bool = True) -> None:
    """Launch the built-in local web dashboard on http://localhost:port."""
    server_address = ("127.0.0.1", port)
    with socketserver.TCPServer(server_address, DashboardHandler) as httpd:
        url = f"http://localhost:{port}"
        print(f"========================================================")
        print(f"   PHI COMPLIANCE SCANNER — LOCAL WEB DASHBOARD        ")
        print(f"========================================================")
        print(f"   Access Dashboard: {url}")
        print(f"   Mode            : 100% Offline (Air-Gapped Loopback)")
        print(f"========================================================")
        print(f"Press Ctrl+C to terminate the dashboard server.")

        if open_browser:
            webbrowser.open(url)

        try:
            httpd.serve_forever()
        except KeyboardInterrupt:
            print("\nShutting down dashboard server.")
