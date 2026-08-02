"""Base types for the ingestion layer.

Every parser yields ``(cell_text, SourceLocation)`` pairs. The recognizer
layer consumes these pairs without knowing anything about the file format.

Design note: source-location specificity is a hard requirement (rules.md §27).
Every finding must point at an exact cell — not just a file or row.
"""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Iterator, Protocol, runtime_checkable


@dataclass(frozen=True, slots=True)
class SourceLocation:
    """Exact provenance of a scanned text chunk within a source file."""

    file_path: Path
    sheet_name: str | None  # None for non-sheet formats (CSV)
    row: int                # 1-indexed; row 1 = header for CSV
    column: str             # column name (CSV header) or letter (XLSX, e.g. "B")

    def __str__(self) -> str:
        if self.sheet_name:
            return f"{self.file_path}!{self.sheet_name}:{self.column}{self.row}"
        return f"{self.file_path}:row={self.row},col={self.column}"

    def as_dict(self) -> dict[str, str]:
        return {
            "file": str(self.file_path),
            "sheet": self.sheet_name or "",
            "row": str(self.row),
            "column": self.column,
        }


@runtime_checkable
class Ingester(Protocol):
    """Protocol satisfied by every format-specific ingester."""

    def ingest(self, path: Path) -> Iterator[tuple[str, SourceLocation]]:
        """Yield ``(cell_text, location)`` for every non-empty cell."""
        ...
