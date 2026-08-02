"""Report generator — CSV and JSON output.

Output format per finding (one row):
  file, sheet, row, column, entity_type, masked_value, confidence

Rollup summary appended at the end of the CSV (as comment rows) and as a
top-level key in the JSON output.

No raw PII values are written to the report — only masked representations.
"""
from __future__ import annotations

import csv
import json
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
