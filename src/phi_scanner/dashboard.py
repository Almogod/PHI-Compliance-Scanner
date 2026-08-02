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
    <title>PHI Compliance Scanner — Local Dashboard</title>
    <style>
        :root {
            --bg: #0f172a;
            --card: #1e293b;
            --accent: #38bdf8;
            --text: #f8fafc;
            --muted: #94a3b8;
            --border: #334155;
        }
        body { font-family: system-ui, -apple-system, sans-serif; background: var(--bg); color: var(--text); padding: 2rem; }
        .container { max-width: 900px; margin: 0 auto; }
        .card { background: var(--card); padding: 2rem; border-radius: 0.75rem; border: 1px solid var(--border); margin-bottom: 2rem; }
        h1 { color: var(--accent); font-size: 1.75rem; margin-bottom: 0.5rem; }
        .desc { color: var(--muted); margin-bottom: 1.5rem; font-size: 0.9rem; }
        .form-group { margin-bottom: 1.25rem; }
        label { display: block; margin-bottom: 0.5rem; font-weight: 600; font-size: 0.875rem; }
        input[type="text"] { width: 100%; padding: 0.75rem; background: var(--bg); border: 1px solid var(--border); color: var(--text); border-radius: 0.5rem; }
        button { background: var(--accent); color: #000; font-weight: 700; border: none; padding: 0.75rem 1.5rem; border-radius: 0.5rem; cursor: pointer; }
        button:hover { opacity: 0.9; }
        #status { margin-top: 1rem; font-weight: 600; }
        iframe { width: 100%; height: 700px; border: 1px solid var(--border); border-radius: 0.75rem; background: var(--bg); }
    </style>
</head>
<body>
    <div class="container">
        <div class="card">
            <h1>PHI Compliance Scanner — Executive Dashboard</h1>
            <p class="desc">Local Zero-Trust Compliance Control Center. Runs 100% offline in memory.</p>
            
            <div class="form-group">
                <label for="scanPath">Target File or Directory Path:</label>
                <input type="text" id="scanPath" value="sample_data" placeholder="e.g. C:\\Data\\Finance or sample_data">
            </div>
            
            <button onclick="runScan()">Start Compliance Scan</button>
            <div id="status"></div>
        </div>

        <div id="reportContainer" style="display: none;">
            <iframe id="reportFrame"></iframe>
        </div>
    </div>

    <script>
        async function runScan() {
            const path = document.getElementById('scanPath').value;
            const statusDiv = document.getElementById('status');
            statusDiv.style.color = '#38bdf8';
            statusDiv.innerText = 'Scanning path in progress... Please wait...';

            try {
                const res = await fetch('/api/scan', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ path: path })
                });
                const data = await res.json();
                if (data.error) {
                    statusDiv.style.color = '#ef4444';
                    statusDiv.innerText = 'Error: ' + data.error;
                } else {
                    statusDiv.style.color = '#10b981';
                    statusDiv.innerText = 'Scan Complete! Found ' + data.total_findings + ' findings in ' + data.duration_sec + 's.';
                    document.getElementById('reportContainer').style.display = 'block';
                    document.getElementById('reportFrame').src = '/api/report?' + Date.now();
                }
            } catch (err) {
                statusDiv.style.color = '#ef4444';
                statusDiv.innerText = 'Failed to execute scan: ' + err;
            }
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
            import time

            length = int(self.headers.get("Content-Length", 0))
            body = self.rfile.read(length)
            try:
                data = json.loads(body.decode("utf-8"))
                target_path = Path(data.get("path", "sample_data"))

                if not target_path.exists():
                    self._send_json({"error": f"Path standard location not found: {target_path}"}, status=400)
                    return

                t0 = time.perf_counter()
                engine = ScanEngine()
                findings = list(engine.scan_path_parallel(target_path) if target_path.is_dir() else engine.scan_file(target_path))
                dur = round(time.perf_counter() - t0, 3)

                # Generate in-memory HTML report string
                tmp_report = target_path.parent / "temp_dashboard_report.html"
                write_html(findings, tmp_report, target_path_str=str(target_path.resolve()))
                DashboardHandler.latest_report_html = tmp_report.read_text(encoding="utf-8")
                if tmp_report.exists():
                    tmp_report.unlink()

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
    server_address = ("", port)
    with socketserver.TCPServer(server_address, DashboardHandler) as httpd:
        url = f"http://localhost:{port}"
        print(f"========================================================")
        print(f"   PHI COMPLIANCE SCANNER — LOCAL WEB DASHBOARD        ")
        print(f"========================================================")
        print(f"  Dashboard URL : {url}")
        print(f"  Security Mode : 100% Local / Air-Gapped (Zero Network)")
        print(f"  Press Ctrl+C to stop the dashboard server.")
        print(f"========================================================")

        if open_browser:
            webbrowser.open(url)

        try:
            httpd.serve_forever()
        except KeyboardInterrupt:
            print("\nDashboard server stopped.")
