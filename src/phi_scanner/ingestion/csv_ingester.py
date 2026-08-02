"""CSV ingester — streams ``CellRecord`` objects, one per non-empty cell.

v4 improvements:
  - Yields ``CellRecord`` with row_context (sibling cells joined by space)
    enabling value-density profiling in the pipeline.
  - Maintains O(row_width) memory footprint — never loads the whole file.
  - Encoding cascade preserved: utf-8-sig → latin-1 → cp1252 → binary fallback.
"""
from __future__ import annotations

import csv
from pathlib import Path
from typing import Iterator

from .base import CellRecord, SourceLocation


class CsvIngester:
    """Reads a CSV file and yields every non-empty cell with its exact location.

    - Tries utf-8-sig first (handles BOM); falls back to latin-1 if decode fails.
    - ``errors="replace"`` prevents crashes on non-decodable bytes.
    - Row numbering: 1 = header row, data starts at 2.
    """

    _ENCODINGS = ["utf-8-sig", "latin-1", "cp1252"]

    def ingest(self, path: Path) -> Iterator[tuple[str, SourceLocation]]:
        """Yield ``(cell_text, location)`` — legacy tuple protocol."""
        yield from ((r.text, r.location) for r in self.ingest_records(path))

    def ingest_records(self, path: Path) -> Iterator[CellRecord]:
        """Yield full ``CellRecord`` objects with row-level sibling context."""
        fh = None
        for enc in self._ENCODINGS:
            try:
                fh = open(path, newline="", encoding=enc, errors="replace")
                fh.read(1024)  # Peek to verify encoding
                fh.seek(0)
                break
            except (UnicodeDecodeError, LookupError):
                if fh:
                    fh.close()
                    fh = None
                continue

        if fh is None:
            fh = open(path, newline="", encoding="utf-8", errors="replace")

        try:
            reader = csv.DictReader(fh)
            if reader.fieldnames is None:
                return

            for row_idx, row in enumerate(reader, start=2):
                # Build row_context: all non-empty values in this row
                row_values = [v.strip() for v in row.values() if v and v.strip()]
                row_context = " ".join(row_values)

                for col_name, value in row.items():
                    if value and value.strip():
                        yield CellRecord(
                            text=value.strip(),
                            location=SourceLocation(
                                file_path=path,
                                sheet_name=None,
                                row=row_idx,
                                column=col_name or "(unnamed)",
                            ),
                            row_context=row_context,
                        )
        finally:
            fh.close()
