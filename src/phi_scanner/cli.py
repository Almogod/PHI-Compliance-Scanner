"""CLI entrypoint — ``scan <path> --output report.csv``.

Usage examples:
  scan --gui                              # Launch CustomTkinter Desktop GUI
  scan ./data/
  scan ./data/employees.xlsx --output findings.csv
  scan ./data/ --output summary.pdf --format pdf
  scan --db "sqlite:///local_database.db" --output db_report.csv
  scan employees.csv -r remediated.csv --remediation-mode tokenize
  scan ./data/ --output secret.phi --encrypt --passphrase "my-secret-key"
"""
from __future__ import annotations

import sys
from pathlib import Path

import click

from .engine import Finding, ScanEngine
from .pipeline import Pipeline
from .redactor import redact_file
from .reporter import write_csv, write_html, write_json, write_encrypted, write_pdf_summary

_CONFIDENCE_ORDER = {"HIGH": 2, "MEDIUM": 1, "LOW": 0}


@click.command()
@click.argument("path", type=click.Path(exists=True, path_type=Path), default=".", required=False)
@click.option(
    "--output", "-o",
    default="report.csv",
    show_default=True,
    help="Output file path (.csv, .json, .html, .pdf, or .phi for encrypted).",
)
@click.option(
    "--format", "fmt",
    type=click.Choice(["csv", "json", "html", "pdf", "encrypted"], case_sensitive=False),
    default=None,
    help="Output format. Inferred from --output extension if not set.",
)
@click.option(
    "--db", "db_uri",
    type=str,
    default=None,
    help="Local database connection URI or file (e.g. 'sqlite:///data.db'). Scans tables in strict read-only mode.",
)
@click.option(
    "--min-confidence",
    type=click.Choice(["HIGH", "MEDIUM", "LOW"], case_sensitive=False),
    default="LOW",
    show_default=True,
    help="Exclude findings below this confidence tier.",
)
@click.option(
    "--workers", "-w",
    type=click.IntRange(min=1, max=32),
    default=4,
    show_default=True,
    help="Number of parallel worker threads for directory scanning (1–32).",
)
@click.option(
    "--summary-file", "-s",
    type=click.Path(path_type=Path),
    default=None,
    help="Optional path to save an audit summary JSON file.",
)
@click.option(
    "--use-agents",
    is_flag=True,
    default=False,
    help="Enable Concurrent Agent Orchestration mode for entity scanning.",
)
@click.option(
    "--redact-output", "-r",
    type=click.Path(path_type=Path),
    default=None,
    help="Optional path to output a remediated copy of the scanned file.",
)
@click.option(
    "--remediation-mode",
    type=click.Choice(["mask", "redact", "tokenize"], case_sensitive=False),
    default="mask",
    show_default=True,
    help="Remediation strategy: 'mask' (XXXX 1234), 'redact' ([REDACTED]), or 'tokenize' (TOK-HMAC).",
)
@click.option(
    "--processes",
    is_flag=True,
    default=False,
    help="Use ProcessPoolExecutor for CPU-bound parallel scanning (GIL bypass).",
)
@click.option(
    "--encrypt",
    is_flag=True,
    default=False,
    help="Write AES-256-GCM encrypted report (.phi format). Requires --passphrase.",
)
@click.option(
    "--passphrase",
    type=str,
    default=None,
    envvar="PHI_SCAN_PASSPHRASE",
    help="Passphrase for encrypted report (--encrypt). Can also be set via PHI_SCAN_PASSPHRASE env var.",
)
@click.option(
    "--gui",
    is_flag=True,
    default=False,
    help="Launch native CustomTkinter desktop GUI application.",
)
@click.option(
    "--web",
    is_flag=True,
    default=False,
    help="Launch local web dashboard UI at http://localhost:8080.",
)
@click.option(
    "--quiet", "-q",
    is_flag=True,
    default=False,
    help="Suppress progress output; only emit errors.",
)
def main(
    path: Path,
    output: str,
    fmt: str | None,
    db_uri: str | None,
    min_confidence: str,
    workers: int,
    summary_file: Path | None,
    use_agents: bool,
    redact_output: Path | None,
    remediation_mode: str,
    processes: bool,
    encrypt: bool,
    passphrase: str | None,
    gui: bool,
    web: bool,
    quiet: bool,
) -> None:
    """Scan PATH (file or directory) or --db for Indian PII identifiers.

    Writes a findings report to OUTPUT with masked values and confidence tiers.
    No scanned content ever leaves this machine — verified by running with
    network access disabled.
    """
    import time
    from collections import Counter
    import json

    if gui:
        from .gui import launch_gui
        launch_gui()
        return

    if web:
        from .dashboard import launch_dashboard
        launch_dashboard()
        return

    start_time = time.perf_counter()
    output_path = Path(output)

    # Infer format from extension if not explicitly set
    if fmt is None:
        ext = output_path.suffix.lower()
        if ext == ".json":
            fmt = "json"
        elif ext in (".html", ".htm"):
            fmt = "html"
        elif ext == ".pdf":
            fmt = "pdf"
        elif ext == ".phi":
            fmt = "encrypted"
        else:
            fmt = "csv"

    # Validate encrypt usage
    if encrypt or fmt == "encrypted":
        fmt = "encrypted"
        if not passphrase:
            click.echo(
                "Error: --encrypt requires a passphrase. Use --passphrase <key> "
                "or set the PHI_SCAN_PASSPHRASE environment variable.",
                err=True,
            )
            sys.exit(1)

    min_rank = _CONFIDENCE_ORDER[min_confidence.upper()]
    engine = ScanEngine()
    pipeline = Pipeline()

    findings: list[Finding] = []

    if db_uri:
        mode_label = f"read-only DB scan ({db_uri})"
    elif use_agents:
        mode_label = f"parallel agents mode (workers: {workers})"
    elif processes:
        mode_label = f"process pool mode (workers: {workers}, GIL-bypass)"
    else:
        mode_label = f"thread pool mode (workers: {workers})"

    target_desc = db_uri if db_uri else str(path)
    if not quiet:
        click.echo(f"Scanning: {target_desc} [{mode_label}]", err=True)

    try:
        if db_uri:
            scanner = pipeline.scan_db(db_uri)
        elif use_agents:
            scanner = engine.scan_path_agents(path, num_agents=workers)
        elif processes and path.is_dir():
            scanner = engine.scan_path_processes(path, max_workers=workers)
        elif path.is_dir():
            scanner = engine.scan_path_parallel(path, max_workers=workers)
        else:
            scanner = engine.scan_file(path)

        for finding in scanner:
            rank = _CONFIDENCE_ORDER.get(finding.confidence, 0)
            if rank >= min_rank:
                findings.append(finding)
    except Exception as exc:
        click.echo(f"Fatal error during scan: {exc}", err=True)
        sys.exit(1)

    duration = time.perf_counter() - start_time
    unique_files = len({str(f.location.file_path) for f in findings})

    if not quiet:
        click.echo(
            f"Done in {duration:.2f}s. {len(findings)} finding(s) across {unique_files} source(s).",
            err=True,
        )

    if not findings:
        click.echo("No findings above threshold. Report not written.", err=True)
        sys.exit(0)

    if fmt == "json":
        write_json(findings, output_path)
    elif fmt == "html":
        write_html(findings, output_path, target_path_str=target_desc)
    elif fmt == "pdf":
        write_pdf_summary(findings, output_path, target_path_str=target_desc)
    elif fmt == "encrypted":
        write_encrypted(findings, output_path, passphrase=passphrase)  # type: ignore[arg-type]
        if not quiet:
            click.echo(
                f"Encrypted report written to: {output_path} "
                f"(AES-256-GCM, PBKDF2-SHA256, {600_000:,} iterations)",
                err=True,
            )
    else:
        write_csv(findings, output_path)

    if not quiet:
        click.echo(f"Report written to: {output_path}", err=True)

    if redact_output:
        if path.is_file():
            redact_count = redact_file(path, redact_output, mode=remediation_mode.lower())
            if not quiet:
                click.echo(
                    f"Remediated copy written to: {redact_output} "
                    f"({redact_count} cells remediated via {remediation_mode.upper()} mode)",
                    err=True,
                )
        else:
            click.echo("Redaction flag requires a single target file.", err=True)

    counts = Counter(f.entity_type for f in findings)
    confidence_counts = Counter(f.confidence for f in findings)

    high_count = confidence_counts.get("HIGH", 0)
    med_count = confidence_counts.get("MEDIUM", 0)

    if high_count > 0:
        risk_level = "CRITICAL RISK (Verified PII Exposure Detected)"
    elif med_count > 0:
        risk_level = "WARNING (Unverified/Pattern PII Candidates Detected)"
    else:
        risk_level = "LOW RISK"

    if not quiet:
        click.echo("\n========================================================")
        click.echo(f"               COMPLIANCE AUDIT SUMMARY                 ")
        click.echo("========================================================")
        click.echo(f"  Target Source    : {target_desc}")
        click.echo(f"  Scan Duration    : {duration:.2f} seconds")
        click.echo(f"  Sources Affected : {unique_files}")
        click.echo(f"  Total Findings   : {len(findings)}")
        click.echo(f"  Executive Status : {risk_level}")
        click.echo("--------------------------------------------------------")
        click.echo("  Entity Breakdown:")
        for entity, count in sorted(counts.items()):
            click.echo(f"    - {entity:<14} : {count}")
        click.echo("--------------------------------------------------------")
        click.echo("  Confidence Breakdown:")
        for conf_tier in ["HIGH", "MEDIUM", "LOW"]:
            if conf_tier in confidence_counts:
                click.echo(f"    - {conf_tier:<14} : {confidence_counts[conf_tier]}")
        click.echo("========================================================\n")

    if summary_file is not None:
        summary_data = {
            "target_source": target_desc,
            "duration_seconds": round(duration, 3),
            "sources_affected": unique_files,
            "total_findings": len(findings),
            "risk_level": risk_level,
            "entity_breakdown": dict(counts),
            "confidence_breakdown": dict(confidence_counts),
        }
        with open(summary_file, "w", encoding="utf-8") as sf:
            json.dump(summary_data, sf, indent=2)
        if not quiet:
            click.echo(f"Audit summary written to: {summary_file}", err=True)


if __name__ == "__main__":
    main()
