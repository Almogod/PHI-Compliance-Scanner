"""Tests for the ingestion layer (CSV and XLSX parsers)."""
from __future__ import annotations

import csv
import io
from pathlib import Path

import openpyxl
import pytest

from phi_scanner.ingestion.csv_ingester import CsvIngester
from phi_scanner.ingestion.xlsx_ingester import XlsxIngester
from phi_scanner.ingestion.base import SourceLocation


# ---------------------------------------------------------------------------
# CSV ingester
# ---------------------------------------------------------------------------

class TestCsvIngester:
    def _write_csv(self, tmp_path: Path, rows: list[dict]) -> Path:
        p = tmp_path / "test.csv"
        with open(p, "w", newline="", encoding="utf-8") as fh:
            writer = csv.DictWriter(fh, fieldnames=list(rows[0].keys()))
            writer.writeheader()
            writer.writerows(rows)
        return p

    def test_yields_cell_text_and_location(self, tmp_path: Path) -> None:
        path = self._write_csv(tmp_path, [
            {"name": "Alice", "uid": "2345678901230"},
        ])
        results = list(CsvIngester().ingest(path))
        texts = [r[0] for r in results]
        assert "Alice" in texts
        assert "2345678901230" in texts

    def test_row_numbering_skips_header(self, tmp_path: Path) -> None:
        path = self._write_csv(tmp_path, [{"a": "v1"}, {"a": "v2"}])
        results = list(CsvIngester().ingest(path))
        rows = [r[1].row for r in results]
        assert 2 in rows   # first data row
        assert 3 in rows   # second data row
        assert 1 not in rows  # header row should not appear as a value

    def test_empty_cells_skipped(self, tmp_path: Path) -> None:
        path = self._write_csv(tmp_path, [{"a": "hello", "b": ""}])
        results = list(CsvIngester().ingest(path))
        assert all(text != "" for text, _ in results)

    def test_location_has_correct_column_name(self, tmp_path: Path) -> None:
        path = self._write_csv(tmp_path, [{"phone": "9876543210"}])
        results = list(CsvIngester().ingest(path))
        assert results[0][1].column == "phone"

    def test_bom_handled(self, tmp_path: Path) -> None:
        # Excel sometimes adds UTF-8 BOM
        p = tmp_path / "bom.csv"
        p.write_bytes(b"\xef\xbb\xbfname,val\r\nAlice,123\r\n")
        results = list(CsvIngester().ingest(p))
        assert any("Alice" in t for t, _ in results)


# ---------------------------------------------------------------------------
# XLSX ingester
# ---------------------------------------------------------------------------

class TestXlsxIngester:
    def _write_xlsx(self, tmp_path: Path, data: dict[str, list[list]]) -> Path:
        p = tmp_path / "test.xlsx"
        wb = openpyxl.Workbook()
        wb.remove(wb.active)
        for sheet_name, rows in data.items():
            ws = wb.create_sheet(sheet_name)
            for row in rows:
                ws.append(row)
        wb.save(p)
        return p

    def test_yields_cell_text_and_location(self, tmp_path: Path) -> None:
        path = self._write_xlsx(tmp_path, {"Sheet1": [["Name", "UID"], ["Alice", "23456789012"]]})
        results = list(XlsxIngester().ingest(path))
        texts = [r[0] for r in results]
        assert "Alice" in texts
        assert "23456789012" in texts

    def test_sheet_name_in_location(self, tmp_path: Path) -> None:
        path = self._write_xlsx(tmp_path, {"Employees": [["uid"], ["9876543210"]]})
        results = list(XlsxIngester().ingest(path))
        assert all(r[1].sheet_name == "Employees" for r in results)

    def test_multi_sheet_scanned(self, tmp_path: Path) -> None:
        path = self._write_xlsx(tmp_path, {
            "Sheet1": [["a"], ["v1"]],
            "Sheet2": [["b"], ["v2"]],
        })
        results = list(XlsxIngester().ingest(path))
        sheet_names = {r[1].sheet_name for r in results}
        assert "Sheet1" in sheet_names
        assert "Sheet2" in sheet_names

    def test_empty_cells_skipped(self, tmp_path: Path) -> None:
        path = self._write_xlsx(tmp_path, {"S": [["a", None, "b"], [None, "v", None]]})
        results = list(XlsxIngester().ingest(path))
        assert all(text.strip() for text, _ in results)

    def test_column_letter_correct(self, tmp_path: Path) -> None:
        path = self._write_xlsx(tmp_path, {"S": [["x", "y", "z"]]})
        results = list(XlsxIngester().ingest(path))
        cols = [r[1].column for r in results]
        assert "A" in cols
        assert "B" in cols
        assert "C" in cols
