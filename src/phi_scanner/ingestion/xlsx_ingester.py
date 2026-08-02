"""XLSX ingester — one ``(cell_text, SourceLocation)`` per non-empty cell.

v2 improvements:
  - Numeric cells: Excel stores all numbers as floats. A cell containing the
    integer 9876543210 yields float 9876543210.0. We convert back to integer
    form when the value is a whole number (no fractional part).
  - Boolean cells: True/False are not identifiers but str(True) = "True".
    Skipped explicitly to avoid noise.
  - Date/datetime cells: str(datetime) produces ISO format, which is noise.
    Skipped explicitly.
  - Error cells: cells with #REF!, #VALUE!, etc. are skipped.
"""
from __future__ import annotations

import datetime
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

                        # Skip booleans, dates, and error values — not identifiers
                        if isinstance(cell.value, bool):
                            continue
                        if isinstance(cell.value, (datetime.datetime, datetime.date, datetime.time)):
                            continue

                        # Convert whole-number floats to int strings
                        # 9876543210.0 → "9876543210" (not "9876543210.0")
                        if isinstance(cell.value, float) and cell.value.is_integer():
                            text = str(int(cell.value))
                        else:
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
