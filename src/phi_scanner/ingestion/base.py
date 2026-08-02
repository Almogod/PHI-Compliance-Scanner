"""Base types for the ingestion layer.

Every parser yields ``(cell_text, SourceLocation)`` pairs. The recognizer
layer consumes these pairs without knowing anything about the file format.

Design note: source-location specificity is a hard requirement (rules.md §27).
Every finding must point at an exact cell — not just a file or row.

v4 extension: CellRecord is the canonical, format-agnostic unit of data flowing
through the pipeline. It wraps the raw text + location and adds row-level
neighbor context for value-density profiling. Ingesters may optionally yield
CellRecord objects directly; the pipeline adapter promotes bare tuples.
"""
from __future__ import annotations

from dataclasses import dataclass, field
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


@dataclass(slots=True)
class CellRecord:
    """Canonical, format-agnostic unit of data produced by every ingester.

    Flows through the pipeline as:
      Ingest → CellRecord → Normalize → Recognize → Aggregate → Report

    Attributes
    ----------
    text:
        The raw cell/chunk content **before** normalization.
    location:
        Exact provenance pointing to the source file, sheet, row, column.
    row_context:
        All non-empty sibling cell values in the same row, joined by space.
        Used by ``detect_row_density()`` for value-density profiling without
        requiring the engine to hold entire rows in memory.
    """

    text: str
    location: SourceLocation
    row_context: str = field(default="")


@runtime_checkable
class Ingester(Protocol):
    """Protocol satisfied by every format-specific ingester."""

    def ingest(self, path: Path) -> Iterator[tuple[str, SourceLocation]]:
        """Yield ``(cell_text, location)`` for every non-empty cell."""
        ...

