"""XLSX ingester — one ``(cell_text, SourceLocation)`` per non-empty cell."""
from __future__ import annotations

from pathlib import Path
from typing import Iterator

import openpyxl
from openpyxl.utils import get_column_letter

from .base import SourceLocation


class XlsxIngester:
    """Opens a workbook in read-only mode to cap memory on large files.

    ``data_only=True`` returns the cached formula result rather than the
    formula string — relevant when cells hold computed identifiers.
    Every sheet in the workbook is scanned in order.
    """

    def ingest(self, path: Path) -> Iterator[tuple[str, SourceLocation]]:
        wb = openpyxl.load_workbook(path, read_only=True, data_only=True)
        try:
            for sheet_name in wb.sheetnames:
                ws = wb[sheet_name]
                for row in ws.iter_rows():
                    for cell in row:
                        if cell.value is None:
                            continue
                        text = str(cell.value).strip()
                        if not text:
                            continue
                        yield text, SourceLocation(
                            file_path=path,
                            sheet_name=sheet_name,
                            row=cell.row,
                            column=get_column_letter(cell.column),
                        )
        finally:
            wb.close()
