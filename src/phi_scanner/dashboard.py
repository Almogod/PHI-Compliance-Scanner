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
    <style>
        :root {
            --bg-dark: oklch(0.14 0.02 255);
            --bg-card: oklch(0.19 0.025 255 / 0.85);
            --bg-card-hover: oklch(0.23 0.03 255);
            --border: oklch(0.28 0.03 255);
            --border-glow: oklch(0.45 0.12 220 / 0.5);
            
            --accent-cyan: oklch(0.75 0.16 220);
            --accent-cyan-hover: oklch(0.82 0.18 215);
            --accent-green: oklch(0.72 0.17 150);
            --accent-amber: oklch(0.78 0.16 70);
            --accent-red: oklch(0.65 0.22 25);
            
            --text-main: oklch(0.96 0.01 255);
            --text-muted: oklch(0.70 0.02 255);
            --text-dim: oklch(0.50 0.02 255);
            
            --font-sans: system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
            --font-mono: ui-monospace, "Cascadia Code", "Fira Code", monospace;
        }

        * { box-sizing: border-box; margin: 0; padding: 0; }
        
        body {
            font-family: var(--font-sans);
            background-color: var(--bg-dark);
            color: var(--text-main);
            min-height: 100vh;
            display: flex;
            flex-direction: column;
            line-height: 1.5;
            -webkit-font-smoothing: antialiased;
        }

        /* Top Navigation Header */
        header {
            background: oklch(0.12 0.02 255 / 0.95);
            backdrop-filter: blur(12px);
            border-bottom: 1px solid var(--border);
            padding: 1rem 2rem;
            display: flex;
            align-items: center;
            justify-content: space-between;
            position: sticky;
            top: 0;
            z-index: 100;
        }

        .brand {
            display: flex;
            align-items: center;
            gap: 0.75rem;
        }

        .brand-logo {
            width: 38px;
            height: 38px;
            background: linear-gradient(135deg, var(--accent-cyan), oklch(0.55 0.20 260));
            border-radius: 0.6rem;
            display: flex;
            align-items: center;
            justify-content: center;
            box-shadow: 0 0 16px oklch(0.75 0.16 220 / 0.35);
        }

        .brand-logo svg {
            width: 22px;
            height: 22px;
            fill: none;
            stroke: #000;
            stroke-width: 2.5;
        }

        .brand-title {
            font-size: 1.15rem;
            font-weight: 700;
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
            background: oklch(0.72 0.17 150 / 0.12);
            border: 1px solid oklch(0.72 0.17 150 / 0.4);
            color: var(--accent-green);
            padding: 0.35rem 0.85rem;
            border-radius: 2rem;
            font-size: 0.75rem;
            font-weight: 600;
            letter-spacing: 0.03em;
            display: flex;
            align-items: center;
            gap: 0.4rem;
        }

        .pulse-dot {
            width: 7px;
            height: 7px;
            background-color: var(--accent-green);
            border-radius: 50%;
            box-shadow: 0 0 8px var(--accent-green);
            animation: pulse 2s infinite;
        }

        @keyframes pulse {
            0%, 100% { opacity: 1; transform: scale(1); }
            50% { opacity: 0.4; transform: scale(0.85); }
        }

        /* Layout Container */
        main {
            max-width: 1300px;
            width: 100%;
            margin: 0 auto;
            padding: 2rem;
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
            padding: 1.75rem;
            box-shadow: 0 10px 30px oklch(0 0 0 / 0.3);
            display: flex;
            flex-direction: column;
            gap: 1.25rem;
            transition: border-color 0.2s;
        }

        .control-panel:focus-within {
            border-color: var(--border-glow);
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
            gap: 0.5rem;
        }

        .quick-paths {
            display: flex;
            align-items: center;
            gap: 0.5rem;
        }

        .path-pill {
            background: oklch(0.22 0.02 255);
            border: 1px solid var(--border);
            color: var(--text-muted);
            padding: 0.25rem 0.65rem;
            border-radius: 0.4rem;
            font-size: 0.75rem;
            font-weight: 500;
            font-family: var(--font-mono);
            cursor: pointer;
            transition: all 0.15s ease;
        }

        .path-pill:hover {
            background: oklch(0.28 0.03 255);
            color: var(--text-main);
            border-color: var(--accent-cyan);
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
            padding: 0.85rem 1.1rem;
            background: oklch(0.12 0.02 255);
            border: 1px solid var(--border);
            border-radius: 0.65rem;
            color: var(--text-main);
            font-family: var(--font-mono);
            font-size: 0.9rem;
            outline: none;
            transition: border-color 0.2s, box-shadow 0.2s;
        }

        .input-wrapper input:focus {
            border-color: var(--accent-cyan);
            box-shadow: 0 0 0 3px oklch(0.75 0.16 220 / 0.15);
        }

        .btn-scan {
            background: linear-gradient(135deg, var(--accent-cyan), oklch(0.68 0.18 230));
            color: #040914;
            font-weight: 700;
            font-size: 0.95rem;
            padding: 0.85rem 2rem;
            border: none;
            border-radius: 0.65rem;
            cursor: pointer;
            display: flex;
            align-items: center;
            gap: 0.6rem;
            box-shadow: 0 4px 14px oklch(0.75 0.16 220 / 0.3);
            transition: transform 0.15s ease, box-shadow 0.15s ease, background 0.2s ease;
            white-space: nowrap;
        }

        .btn-scan:hover {
            transform: translateY(-1px);
            box-shadow: 0 6px 20px oklch(0.75 0.16 220 / 0.45);
            background: linear-gradient(135deg, var(--accent-cyan-hover), oklch(0.72 0.18 225));
        }

        .btn-scan:active {
            transform: translateY(0);
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
            gap: 1.5rem;
            font-size: 0.825rem;
            color: var(--text-muted);
            padding-top: 0.5rem;
            border-top: 1px dashed var(--border);
        }

        .checkbox-label {
            display: flex;
            align-items: center;
            gap: 0.5rem;
            cursor: pointer;
            user-select: none;
        }

        .checkbox-label input {
            accent-color: var(--accent-cyan);
            width: 15px;
            height: 15px;
            cursor: pointer;
        }

        /* Scan Status Bar */
        #statusBox {
            display: none;
            padding: 0.85rem 1.1rem;
            border-radius: 0.65rem;
            font-size: 0.875rem;
            font-weight: 500;
            display: flex;
            align-items: center;
            gap: 0.75rem;
        }

        .spinner {
            width: 18px;
            height: 18px;
            border: 2px solid oklch(0.75 0.16 220 / 0.3);
            border-top-color: var(--accent-cyan);
            border-radius: 50%;
            animation: spin 0.8s linear infinite;
        }

        @keyframes spin {
            to { transform: rotate(360deg); }
        }

        /* KPI Stat Cards Grid */
        .stats-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(240px, 1fr));
            gap: 1.25rem;
        }

        .stat-card {
            background: var(--bg-card);
            border: 1px solid var(--border);
            border-radius: 0.85rem;
            padding: 1.25rem 1.5rem;
            display: flex;
            flex-direction: column;
            gap: 0.5rem;
        }

        .stat-label {
            font-size: 0.75rem;
            text-transform: uppercase;
            letter-spacing: 0.05em;
            color: var(--text-muted);
            font-weight: 600;
        }

        .stat-value {
            font-size: 1.8rem;
            font-weight: 800;
            letter-spacing: -0.03em;
            color: var(--text-main);
            font-family: var(--font-mono);
        }

        .stat-desc {
            font-size: 0.8rem;
            color: var(--text-dim);
        }

        .badge-risk {
            display: inline-flex;
            align-items: center;
            padding: 0.25rem 0.75rem;
            border-radius: 0.4rem;
            font-size: 0.825rem;
            font-weight: 700;
            width: fit-content;
        }

        .badge-risk.critical {
            background: oklch(0.65 0.22 25 / 0.15);
            color: var(--accent-red);
            border: 1px solid oklch(0.65 0.22 25 / 0.4);
        }

        .badge-risk.low {
            background: oklch(0.72 0.17 150 / 0.15);
            color: var(--accent-green);
            border: 1px solid oklch(0.72 0.17 150 / 0.4);
        }

        /* Report Frame Container */
        .report-section {
            background: var(--bg-card);
            border: 1px solid var(--border);
            border-radius: 1rem;
            overflow: hidden;
            box-shadow: 0 10px 30px oklch(0 0 0 / 0.3);
            display: flex;
            flex-direction: column;
            min-height: 750px;
        }

        .report-toolbar {
            background: oklch(0.12 0.02 255);
            padding: 0.85rem 1.5rem;
            border-bottom: 1px solid var(--border);
            display: flex;
            align-items: center;
            justify-content: space-between;
        }

        .toolbar-title {
            font-size: 0.875rem;
            font-weight: 600;
            color: var(--text-muted);
            display: flex;
            align-items: center;
            gap: 0.5rem;
        }

        .toolbar-actions {
            display: flex;
            gap: 0.75rem;
        }

        .btn-action {
            background: oklch(0.20 0.02 255);
            border: 1px solid var(--border);
            color: var(--text-muted);
            padding: 0.35rem 0.85rem;
            border-radius: 0.4rem;
            font-size: 0.75rem;
            font-weight: 600;
            cursor: pointer;
            transition: all 0.15s ease;
        }

        .btn-action:hover {
            background: oklch(0.26 0.03 255);
            color: var(--text-main);
            border-color: var(--accent-cyan);
        }

        iframe {
            width: 100%;
            height: 750px;
            border: none;
            background: #0f172a;
        }

        .empty-state {
            padding: 5rem 2rem;
            text-align: center;
            color: var(--text-muted);
            display: flex;
            flex-direction: column;
            align-items: center;
            gap: 1rem;
        }

        .empty-icon {
            width: 56px;
            height: 56px;
            background: oklch(0.20 0.025 255);
            border-radius: 50%;
            display: flex;
            align-items: center;
            justify-content: center;
            color: var(--accent-cyan);
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
                <div class="brand-subtitle">DPDP Act Data Sanitization & Audit Engine v3.0</div>
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
                    <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="var(--accent-cyan)" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round">
                        <circle cx="11" cy="11" r="8"></circle>
                        <line x1="21" y1="21" x2="16.65" y2="16.65"></line>
                    </svg>
                    Scan Target Directory or Document
                </div>
                
                <div class="quick-paths">
                    <span style="font-size: 0.75rem; color: var(--text-dim);">Quick Select:</span>
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
                <div class="stat-desc">Aadhaar, PAN, Passport, Voter ID, Mobile</div>
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
            statusBox.style.background = 'oklch(0.20 0.025 255)';
            statusBox.style.color = 'var(--accent-cyan)';
            statusText.innerText = 'Scanning path in progress... Please wait...';

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
                    statusBox.style.background = 'oklch(0.65 0.22 25 / 0.15)';
                    statusBox.style.color = 'var(--accent-red)';
                    statusText.innerText = 'Scan Error: ' + data.error;
                } else {
                    statusBox.style.background = 'oklch(0.72 0.17 150 / 0.15)';
                    statusBox.style.color = 'var(--accent-green)';
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
                statusBox.style.background = 'oklch(0.65 0.22 25 / 0.15)';
                statusBox.style.color = 'var(--accent-red)';
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

                # --- path-traversal guard ---
                # Resolve to absolute path and verify it does not escape
                # the current working directory or temp dir.
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
                    # Allow absolute paths that are under cwd or /tmp — reject everything else
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

                # Execute redaction if requested and target is a single file
                if do_redact and target_path.is_file():
                    from .redactor import redact_file
                    redact_out = target_path.parent / f"redacted_{target_path.name}"
                    redact_file(target_path, redact_out)

                # Write temp report to system temp dir (not the scan target dir)
                # to avoid PermissionError on read-only scan directories.
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
    """Launch the built-in local web dashboard on http://localhost:port.

    Binds to 127.0.0.1 only (loopback) — never reachable from other machines
    on the same network, preserving the air-gapped security guarantee.
    """
    # Loopback-only: never bind to "" (all interfaces) as that exposes the
    # scan API (arbitrary file read) to anyone on the same LAN segment.
    server_address = ("127.0.0.1", port)
    with socketserver.TCPServer(server_address, DashboardHandler) as httpd:
        url = f"http://localhost:{port}"
        print(f"========================================================")
        print(f"   PHI COMPLIANCE SCANNER — LOCAL WEB DASHBOARD        ")
        print(f"========================================================")
        print(f"  Dashboard URL : {url}")
        print(f"  Security Mode : 127.0.0.1 loopback-only (LAN-isolated)")
        print(f"  Press Ctrl+C to stop the dashboard server.")
        print(f"========================================================")

        if open_browser:
            webbrowser.open(url)

        try:
            httpd.serve_forever()
        except KeyboardInterrupt:
            print("\nDashboard server stopped.")
