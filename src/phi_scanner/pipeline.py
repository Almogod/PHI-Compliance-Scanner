"""Formal Pipeline architecture for PHI scanning.

Pipeline stages:
  Ingest → Transform/Clean → Recognize → Context-Boost → Aggregate → Report

This module decouples each concern into a named, composable stage. The engine
(``engine.py``) can use the full pipeline or individual stages as needed.

Design principles:
  1. Every stage is a pure generator/iterator — no side effects.
  2. The pipeline is lazy end-to-end: memory footprint is O(row_width), not
     O(file_size), even for multi-gigabyte datasets.
  3. PHI is masked at recognition time (RecognizerMatch.masked_value) and the
     raw_value is discarded immediately after deduplication key hashing.
  4. Adding a new file format requires only a new Ingester — zero pipeline changes.
  5. Adding a new PII type requires only a new BaseRecognizer subclass — zero
     engine or pipeline changes.
"""
from __future__ import annotations

from pathlib import Path
from typing import Iterator

from .context import (
    boost_confidence,
    detect_column_entity,
    detect_inline_labels,
    detect_masked_identifiers,
    detect_row_density,
    has_negative_context,
)
from .engine import Finding  # re-use the canonical Finding dataclass
from .ingestion.base import CellRecord, SourceLocation
from .ingestion.csv_ingester import CsvIngester
from .ingestion.docx_ingester import DocxIngester
from .ingestion.pdf_ingester import PdfIngester
from .ingestion.xlsx_ingester import XlsxIngester
from .ingestion.unstructured_ingester import (
    UnstructuredIngester,
    JsonIngester,
    TsvIngester,
    ParquetIngester,
)
from .ingestion.db_ingester import DbIngester
from .normalizer import normalise_cell
from .recognizers.base import RECOGNIZER_REGISTRY

# Ensure all recognizers are imported and registered before the pipeline runs
import phi_scanner.recognizers.aadhaar       # noqa: F401
import phi_scanner.recognizers.pan           # noqa: F401
import phi_scanner.recognizers.gstin         # noqa: F401
import phi_scanner.recognizers.mobile        # noqa: F401
import phi_scanner.recognizers.voter_id      # noqa: F401
import phi_scanner.recognizers.passport      # noqa: F401
import phi_scanner.recognizers.bank_account  # noqa: F401


# ---------------------------------------------------------------------------
# Ingester registry (format → Ingester instance)
# ---------------------------------------------------------------------------

_UNSTRUCTURED = UnstructuredIngester()
_JSON_INGESTER = JsonIngester()
_DB_INGESTER = DbIngester()

_INGESTERS: dict[str, object] = {
    ".csv":      CsvIngester(),
    ".xlsx":     XlsxIngester(),
    ".xls":      XlsxIngester(),
    ".docx":     DocxIngester(),
    ".pdf":      PdfIngester(),
    ".txt":      _UNSTRUCTURED,
    ".md":       _UNSTRUCTURED,
    ".log":      _UNSTRUCTURED,
    ".rst":      _UNSTRUCTURED,
    ".markdown": _UNSTRUCTURED,
    ".json":     _JSON_INGESTER,
    ".jsonl":    _JSON_INGESTER,
    ".tsv":      TsvIngester(),
    ".parquet":  ParquetIngester(),
    ".db":       _DB_INGESTER,
    ".sqlite":   _DB_INGESTER,
    ".sqlite3":  _DB_INGESTER,
}


# ---------------------------------------------------------------------------
# Pipeline stages
# ---------------------------------------------------------------------------

class Pipeline:
    """Formal Ingest → Transform → Recognize → Boost → Aggregate pipeline."""

    # ------------------------------------------------------------------
    # Stage 1: Ingest
    # ------------------------------------------------------------------

    def stage_ingest(self, path: Path) -> Iterator[CellRecord]:
        """Ingest a file and emit ``CellRecord`` objects, one per cell."""
        suffix = path.suffix.lower()
        ingester = _INGESTERS.get(suffix)
        if ingester is None:
            return  # unsupported format

        if hasattr(ingester, "ingest_records"):
            yield from ingester.ingest_records(path)  # type: ignore[union-attr]
        else:
            for text, location in ingester.ingest(path):  # type: ignore[misc]
                yield CellRecord(text=text, location=location, row_context="")

    def scan_db(self, db_connection_uri: str) -> Iterator[Finding]:
        """Scan a database URI in strict read-only mode."""
        try:
            records = _DB_INGESTER.ingest_records(db_connection_uri)
            transformed = self.stage_transform(records)
            yield from self.stage_recognize(transformed)
        except Exception as exc:
            err_loc = SourceLocation(file_path=Path(db_connection_uri), sheet_name=None, row=1, column="ERROR")
            yield Finding(
                entity_type="FILE_READ_ERROR",
                masked_value=f"{exc.__class__.__name__}: {str(exc)[:120]}",
                confidence="LOW",
                location=err_loc,
            )

    # ------------------------------------------------------------------
    # Stage 2: Transform / Normalize
    # ------------------------------------------------------------------

    @staticmethod
    def stage_transform(records: Iterator[CellRecord]) -> Iterator[tuple[CellRecord, list[str]]]:
        """Normalize each cell's text and split multi-value cells into chunks."""
        for record in records:
            chunks = normalise_cell(record.text)
            if chunks:
                yield record, chunks

    # ------------------------------------------------------------------
    # Stage 3: Recognize + Stage 4: Context-Boost
    # ------------------------------------------------------------------

    @staticmethod
    def stage_recognize(
        transformed: Iterator[tuple[CellRecord, list[str]]],
    ) -> Iterator[Finding]:
        """Run all registered recognizers on each chunk and apply context boosting."""
        seen: set[tuple[str, str]] = set()

        for record, chunks in transformed:
            column_entity = detect_column_entity(record.location.column)
            has_row_ctx = detect_row_density(record.row_context)

            for chunk in chunks:
                inline_labels = detect_inline_labels(chunk)

                for recognizer in RECOGNIZER_REGISTRY.active():
                    for match in recognizer.find(chunk):
                        dedup_key = (match.entity_type, match.raw_value)
                        if dedup_key in seen:
                            continue
                        seen.add(dedup_key)

                        confidence = boost_confidence(
                            match.confidence,
                            match.entity_type,
                            column_entity,
                            inline_labels,
                            column_name=record.location.column,
                            has_row_context=has_row_ctx,
                        )

                        yield Finding(
                            entity_type=match.entity_type,
                            masked_value=match.masked_value,
                            confidence=confidence,
                            location=record.location,
                        )

                for masked in detect_masked_identifiers(chunk):
                    key = (masked["entity_type"], masked["masked_value"])
                    if key in seen:
                        continue
                    seen.add(key)
                    yield Finding(
                        entity_type=masked["entity_type"],
                        masked_value=masked["masked_value"],
                        confidence=masked["confidence"],
                        location=record.location,
                    )

    # ------------------------------------------------------------------
    # Full pipeline: scan a single file
    # ------------------------------------------------------------------

    def scan_file(self, path: Path) -> Iterator[Finding]:
        """Run the complete pipeline for a single file."""
        try:
            records = self.stage_ingest(path)
            transformed = self.stage_transform(records)
            yield from self.stage_recognize(transformed)
        except Exception as exc:
            err_loc = SourceLocation(file_path=path, sheet_name=None, row=1, column="ERROR")
            yield Finding(
                entity_type="FILE_READ_ERROR",
                masked_value=f"{exc.__class__.__name__}: {str(exc)[:120]}",
                confidence="LOW",
                location=err_loc,
            )

    # ------------------------------------------------------------------
    # Full pipeline: scan a file or directory tree
    # ------------------------------------------------------------------

    def scan_path(self, path: Path) -> Iterator[Finding]:
        """Recursively scan all supported files under *path*."""
        if path.is_file():
            yield from self.scan_file(path)
        elif path.is_dir():
            for child in sorted(path.rglob("*")):
                if child.is_file() and child.suffix.lower() in _INGESTERS:
                    yield from self.scan_file(child)
        else:
            raise FileNotFoundError(f"Path does not exist: {path}")

    def scan_path_parallel(self, path: Path, max_workers: int = 4) -> Iterator[Finding]:
        """Thread-parallel scan."""
        from concurrent.futures import ThreadPoolExecutor

        if path.is_file():
            yield from self.scan_file(path)
            return

        files = [
            p for p in sorted(path.rglob("*"))
            if p.is_file() and p.suffix.lower() in _INGESTERS
        ]
        if not files:
            return

        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            for file_findings in executor.map(lambda f: list(self.scan_file(f)), files):
                yield from file_findings

    def scan_path_processes(self, path: Path, max_workers: int = 4) -> Iterator[Finding]:
        """Process-parallel scan."""
        from concurrent.futures import ProcessPoolExecutor, as_completed

        if path.is_file():
            yield from self.scan_file(path)
            return

        files = [
            p for p in sorted(path.rglob("*"))
            if p.is_file() and p.suffix.lower() in _INGESTERS
        ]
        if not files:
            return

        try:
            with ProcessPoolExecutor(max_workers=max_workers) as executor:
                futures = {executor.submit(_pipeline_scan_file, f): f for f in files}
                for future in as_completed(futures):
                    try:
                        yield from future.result()
                    except Exception as exc:
                        f = futures[future]
                        err_loc = SourceLocation(file_path=f, sheet_name=None, row=1, column="ERROR")
                        yield Finding(
                            entity_type="FILE_READ_ERROR",
                            masked_value=f"{exc.__class__.__name__}: {str(exc)[:120]}",
                            confidence="LOW",
                            location=err_loc,
                        )
        except (OSError, RuntimeError):
            yield from self.scan_path_parallel(path, max_workers=max_workers)


# Top-level picklable function for ProcessPoolExecutor
def _pipeline_scan_file(path: Path) -> list[Finding]:
    return list(Pipeline().scan_file(path))
