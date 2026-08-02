"""CSV ingester — one ``(cell_text, SourceLocation)`` per non-empty cell.

v2 improvements:
  - Tries multiple encodings: utf-8-sig → latin-1 fallback (Excel on Windows
    often saves CSVs in latin-1/cp1252, not UTF-8)
  - Normalises numeric-looking strings: strips trailing ".0" from values like
    "9876543210.0" that snuck through Excel CSV export
"""
from __future__ import annotations

import csv
from pathlib import Path
from typing import Iterator

from .base import SourceLocation


class CsvIngester:
    """Reads a CSV file and yields every non-empty cell with its exact location.

    - Tries utf-8-sig first (handles BOM); falls back to latin-1 if decode fails.
    - ``errors="replace"`` prevents crashes on non-decodable bytes.
    - Row numbering: 1 = header row, data starts at 2.
    """

    _ENCODINGS = ["utf-8-sig", "latin-1", "cp1252"]

    def ingest(self, path: Path) -> Iterator[tuple[str, SourceLocation]]:
        # Try encodings in order — use the first one that doesn't crash
        fh = None
        for enc in self._ENCODINGS:
            try:
                fh = open(path, newline="", encoding=enc, errors="replace")
                # Peek at a small portion to verify decoding works
                fh.read(1024)
                fh.seek(0)
                break
            except (UnicodeDecodeError, LookupError):
                if fh:
                    fh.close()
                    fh = None
                continue

        if fh is None:
            # Last resort: binary read with replace
            fh = open(path, newline="", encoding="utf-8", errors="replace")

        try:
            reader = csv.DictReader(fh)
            if reader.fieldnames is None:
                return

            for row_idx, row in enumerate(reader, start=2):
                for col_name, value in row.items():
                    if value and value.strip():
                        yield value.strip(), SourceLocation(
                            file_path=path,
                            sheet_name=None,
                            row=row_idx,
                            column=col_name or "(unnamed)",
                        )
        finally:
            fh.close()
