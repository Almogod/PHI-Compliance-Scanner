"""CLI entrypoint — ``scan <path> --output report.csv``.

Usage examples:
  scan ./data/
  scan ./data/employees.xlsx --output findings.csv
  scan ./data/ --output findings.json --format json
  scan ./data/ --min-confidence MEDIUM
"""
from __future__ import annotations

import sys
from pathlib import Path

import click

from .engine import Finding, ScanEngine
from .redactor import redact_file
from .reporter import write_csv, write_html, write_json

_CONFIDENCE_ORDER = {"HIGH": 2, "MEDIUM": 1, "LOW": 0}


@click.command()
@click.argument("path", type=click.Path(exists=True, path_type=Path))
@click.option(
    "--output", "-o",
    default="report.csv",
    show_default=True,
    help="Output file path (.csv, .json, or .html).",
)
@click.option(
    "--format", "fmt",
    type=click.Choice(["csv", "json", "html"], case_sensitive=False),
    default=None,
    help="Output format. Inferred from --output extension if not set.",
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
    type=int,
    default=4,
    show_default=True,
    help="Number of parallel worker threads for directory scanning.",
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
    help="Optional path to output a redacted/sanitized copy of the scanned file.",
)
@click.option(
    "--web", "--gui",
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
    min_confidence: str,
    workers: int,
    summary_file: Path | None,
    use_agents: bool,
    redact_output: Path | None,
    web: bool,
    quiet: bool,
) -> None:
    """Scan PATH (file or directory) for Indian PII identifiers.

    Writes a findings report to OUTPUT with masked values and confidence tiers.
    No scanned content ever leaves this machine — verified by running with
    network access disabled.
    """
    import time
    from collections import Counter
    import json

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
        else:
            fmt = "csv"

    min_rank = _CONFIDENCE_ORDER[min_confidence.upper()]
    engine = ScanEngine()

    findings: list[Finding] = []

    mode_label = f"parallel agents mode (workers: {workers})" if use_agents else f"parallel mode (workers: {workers})"
    if not quiet:
        click.echo(f"Scanning: {path} [{mode_label}]", err=True)

    try:
        if use_agents:
            scanner = engine.scan_path_agents(path, num_agents=workers)
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
            f"Done in {duration:.2f}s. {len(findings)} finding(s) across {unique_files} file(s).",
            err=True,
        )

    if not findings:
        click.echo("No findings above threshold. Report not written.", err=True)
        sys.exit(0)

    if fmt == "json":
        write_json(findings, output_path)
    elif fmt == "html":
        write_html(findings, output_path, target_path_str=str(path.resolve()))
    else:
        write_csv(findings, output_path)

    if not quiet:
        click.echo(f"Report written to: {output_path}", err=True)

    if redact_output:
        if path.is_file():
            redact_count = redact_file(path, redact_output)
            if not quiet:
                click.echo(f"Redacted copy written to: {redact_output} ({redact_count} cells sanitized)", err=True)
        else:
            click.echo("Redaction flag requires a single target file (directory redaction coming in v2.1).", err=True)

    # Calculate summary metrics & Executive Risk Level
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
        click.echo(f"  Target Path      : {path.resolve()}")
        click.echo(f"  Scan Duration    : {duration:.2f} seconds")
        click.echo(f"  Files Affected   : {unique_files}")
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

    # Optional Audit Summary JSON File
    if summary_file is not None:
        summary_data = {
            "target_path": str(path.resolve()),
            "duration_seconds": round(duration, 3),
            "files_affected": unique_files,
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
