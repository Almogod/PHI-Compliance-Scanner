"""Ingester for unstructured text files, JSON/JSONL, TSV, and tabular formats.

Provides streaming CellRecord extraction for:
  - Plain text & unstructured docs (.txt, .md, .log, .rst, .markdown)
  - JSON & JSONL (.json, .jsonl)
  - TSV (.tsv)
  - Parquet (.parquet) via optional pyarrow/pandas engine
"""
from __future__ import annotations

import csv
import json
from pathlib import Path
from typing import Iterator

from .base import CellRecord, SourceLocation


class UnstructuredIngester:
    """Ingester for unstructured text files (.txt, .md, .log, .rst)."""

    def ingest(self, path: Path) -> Iterator[tuple[str, SourceLocation]]:
        for record in self.ingest_records(path):
            yield record.text, record.location

    def ingest_records(self, path: Path) -> Iterator[CellRecord]:
        try:
            with open(path, "r", encoding="utf-8", errors="replace") as f:
                lines = f.readlines()
        except Exception:
            return

        total_lines = len(lines)
        for idx, line in enumerate(lines, start=1):
            text = line.strip()
            if not text:
                continue

            # Build surrounding context (sibling lines)
            prev_line = lines[idx - 2].strip() if idx > 1 else ""
            next_line = lines[idx].strip() if idx < total_lines else ""
            ctx = f"{prev_line} {text} {next_line}".strip()

            loc = SourceLocation(file_path=path, sheet_name=None, row=idx, column="text")
            yield CellRecord(text=text, location=loc, row_context=ctx)


class JsonIngester:
    """Ingester for JSON and JSONL documents (.json, .jsonl)."""

    def ingest(self, path: Path) -> Iterator[tuple[str, SourceLocation]]:
        for record in self.ingest_records(path):
            yield record.text, record.location

    def ingest_records(self, path: Path) -> Iterator[CellRecord]:
        suffix = path.suffix.lower()
        if suffix == ".jsonl":
            yield from self._ingest_jsonl(path)
        else:
            yield from self._ingest_json(path)

    def _ingest_jsonl(self, path: Path) -> Iterator[CellRecord]:
        try:
            with open(path, "r", encoding="utf-8", errors="replace") as f:
                for row_idx, line in enumerate(f, start=1):
                    line_str = line.strip()
                    if not line_str:
                        continue
                    try:
                        obj = json.loads(line_str)
                        if isinstance(obj, dict):
                            row_ctx = " ".join(str(v) for v in obj.values() if v is not None)
                            yield from self._flatten_dict(obj, path, row_idx, row_ctx)
                        else:
                            loc = SourceLocation(file_path=path, sheet_name=None, row=row_idx, column="value")
                            yield CellRecord(text=str(obj), location=loc, row_context=str(obj))
                    except Exception:
                        loc = SourceLocation(file_path=path, sheet_name=None, row=row_idx, column="raw_line")
                        yield CellRecord(text=line_str, location=loc, row_context=line_str)
        except Exception:
            return

    def _ingest_json(self, path: Path) -> Iterator[CellRecord]:
        try:
            with open(path, "r", encoding="utf-8", errors="replace") as f:
                data = json.load(f)
        except Exception:
            return

        if isinstance(data, list):
            for row_idx, item in enumerate(data, start=1):
                if isinstance(item, dict):
                    row_ctx = " ".join(str(v) for v in item.values() if v is not None)
                    yield from self._flatten_dict(item, path, row_idx, row_ctx)
                else:
                    loc = SourceLocation(file_path=path, sheet_name=None, row=row_idx, column="item")
                    yield CellRecord(text=str(item), location=loc, row_context=str(item))
        elif isinstance(data, dict):
            row_ctx = " ".join(str(v) for v in data.values() if v is not None)
            yield from self._flatten_dict(data, path, 1, row_ctx)

    def _flatten_dict(
        self, obj: dict, path: Path, row: int, row_context: str, prefix: str = ""
    ) -> Iterator[CellRecord]:
        for k, v in obj.items():
            key_path = f"{prefix}.{k}" if prefix else str(k)
            if isinstance(v, dict):
                yield from self._flatten_dict(v, path, row, row_context, prefix=key_path)
            elif isinstance(v, list):
                for idx, elem in enumerate(v):
                    elem_key = f"{key_path}[{idx}]"
                    if isinstance(elem, dict):
                        yield from self._flatten_dict(elem, path, row, row_context, prefix=elem_key)
                    elif elem is not None:
                        loc = SourceLocation(file_path=path, sheet_name=None, row=row, column=elem_key)
                        yield CellRecord(text=str(elem), location=loc, row_context=row_context)
            elif v is not None:
                loc = SourceLocation(file_path=path, sheet_name=None, row=row, column=key_path)
                yield CellRecord(text=str(v), location=loc, row_context=row_context)


class TsvIngester:
    """Ingester for tab-separated value (.tsv) files."""

    def ingest(self, path: Path) -> Iterator[tuple[str, SourceLocation]]:
        for record in self.ingest_records(path):
            yield record.text, record.location

    def ingest_records(self, path: Path) -> Iterator[CellRecord]:
        try:
            with open(path, "r", encoding="utf-8-sig", errors="replace", newline="") as f:
                reader = csv.reader(f, delimiter="\t")
                header: list[str] | None = None
                for row_idx, row in enumerate(reader, start=1):
                    if not row:
                        continue
                    if header is None:
                        header = [col.strip() for col in row]
                        continue

                    row_ctx = " ".join(cell for cell in row if cell)
                    for col_idx, cell_value in enumerate(row):
                        if not cell_value or not cell_value.strip():
                            continue
                        col_name = header[col_idx] if col_idx < len(header) else f"col_{col_idx+1}"
                        loc = SourceLocation(file_path=path, sheet_name=None, row=row_idx, column=col_name)
                        yield CellRecord(text=cell_value.strip(), location=loc, row_context=row_ctx)
        except Exception:
            return


class ParquetIngester:
    """Ingester for Apache Parquet (.parquet) files."""

    def ingest(self, path: Path) -> Iterator[tuple[str, SourceLocation]]:
        for record in self.ingest_records(path):
            yield record.text, record.location

    def ingest_records(self, path: Path) -> Iterator[CellRecord]:
        try:
            import pandas as pd
            df = pd.read_parquet(path)
            for row_idx, row in df.iterrows():
                row_num = int(row_idx) + 1  # type: ignore[call-overload]
                row_ctx = " ".join(str(v) for v in row.values if pd.notna(v))
                for col_name in df.columns:
                    val = row[col_name]
                    if pd.notna(val):
                        loc = SourceLocation(file_path=path, sheet_name=None, row=row_num, column=str(col_name))
                        yield CellRecord(text=str(val), location=loc, row_context=row_ctx)
        except Exception:
            return
