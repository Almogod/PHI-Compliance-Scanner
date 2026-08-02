"""CSV ingester — one ``(cell_text, SourceLocation)`` per non-empty cell."""
from __future__ import annotations

import csv
from pathlib import Path
from typing import Iterator

from .base import SourceLocation


class CsvIngester:
    """Reads a CSV file and yields every non-empty cell with its exact location.

    - Opens with ``utf-8-sig`` to transparently strip Excel BOM headers.
    - ``errors="replace"`` prevents crashes on non-UTF-8 bytes; callers see
      ``\ufffd`` replacement characters, which will not match any identifier
      pattern — safe degradation, not silent data loss.
    - Row numbering: 1 = header row, data starts at 2.
    """

    def ingest(self, path: Path) -> Iterator[tuple[str, SourceLocation]]:
        with open(path, newline="", encoding="utf-8-sig", errors="replace") as fh:
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
