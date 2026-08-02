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
from .reporter import write_csv, write_json

_CONFIDENCE_ORDER = {"HIGH": 2, "MEDIUM": 1, "LOW": 0}


@click.command()
@click.argument("path", type=click.Path(exists=True, path_type=Path))
@click.option(
    "--output", "-o",
    default="report.csv",
    show_default=True,
    help="Output file path (.csv or .json).",
)
@click.option(
    "--format", "fmt",
    type=click.Choice(["csv", "json"], case_sensitive=False),
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
    quiet: bool,
) -> None:
    """Scan PATH (file or directory) for Indian PII identifiers.

    Writes a findings report to OUTPUT with masked values and confidence tiers.
    No scanned content ever leaves this machine — verified by running with
    network access disabled.
    """
    output_path = Path(output)

    # Infer format from extension if not explicitly set
    if fmt is None:
        fmt = "json" if output_path.suffix.lower() == ".json" else "csv"

    min_rank = _CONFIDENCE_ORDER[min_confidence.upper()]
    engine = ScanEngine()

    findings: list[Finding] = []
    file_count = 0

    if not quiet:
        click.echo(f"Scanning: {path}", err=True)

    for finding in engine.scan_path(path):
        rank = _CONFIDENCE_ORDER.get(finding.confidence, 0)
        if rank >= min_rank:
            findings.append(finding)
        loc = finding.location
        if not quiet:
            # Count unique files seen
            pass

    # Count unique files from findings
    unique_files = len({str(f.location.file_path) for f in findings})

    if not quiet:
        click.echo(
            f"Done. {len(findings)} finding(s) across {unique_files} file(s).",
            err=True,
        )

    if not findings:
        click.echo("No findings above threshold. Report not written.", err=True)
        sys.exit(0)

    if fmt == "json":
        write_json(findings, output_path)
    else:
        write_csv(findings, output_path)

    if not quiet:
        click.echo(f"Report written to: {output_path}", err=True)

    # Print summary table to stdout
    from collections import Counter
    counts = Counter(f.entity_type for f in findings)
    click.echo("\nSummary")
    click.echo("-------")
    for entity, count in sorted(counts.items()):
        click.echo(f"  {entity:<12} {count}")
    click.echo(f"\n  TOTAL        {len(findings)}")


if __name__ == "__main__":
    main()
