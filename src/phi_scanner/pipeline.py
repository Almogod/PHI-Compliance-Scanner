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

Concurrency note:
  ``Pipeline.scan_file()`` is safe to call from multiple threads or processes
  simultaneously because all state is local to each generator frame.
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

_INGESTERS: dict[str, object] = {
    ".csv":  CsvIngester(),
    ".xlsx": XlsxIngester(),
    ".xls":  XlsxIngester(),
    ".docx": DocxIngester(),
    ".pdf":  PdfIngester(),
}


# ---------------------------------------------------------------------------
# Pipeline stages
# ---------------------------------------------------------------------------

class Pipeline:
    """Formal Ingest → Transform → Recognize → Boost → Aggregate pipeline.

    Each public method corresponds to one composable pipeline stage. The
    ``scan_file()`` and ``scan_path()`` methods run the full pipeline.

    Usage
    -----
    findings = list(Pipeline().scan_path(Path("./data")))
    """

    # ------------------------------------------------------------------
    # Stage 1: Ingest
    # ------------------------------------------------------------------

    def stage_ingest(self, path: Path) -> Iterator[CellRecord]:
        """Ingest a file and emit ``CellRecord`` objects, one per cell.

        Uses ``ingest_records()`` when available (CSV/XLSX) to capture
        row-level sibling context. Falls back to bare tuple protocol for
        other ingesters (DOCX, PDF).
        """
        suffix = path.suffix.lower()
        ingester = _INGESTERS.get(suffix)
        if ingester is None:
            return  # unsupported format

        if hasattr(ingester, "ingest_records"):
            yield from ingester.ingest_records(path)  # type: ignore[union-attr]
        else:
            # Legacy tuple protocol — no row context available
            for text, location in ingester.ingest(path):  # type: ignore[misc]
                yield CellRecord(text=text, location=location, row_context="")

    # ------------------------------------------------------------------
    # Stage 2: Transform / Normalize
    # ------------------------------------------------------------------

    @staticmethod
    def stage_transform(records: Iterator[CellRecord]) -> Iterator[tuple[CellRecord, list[str]]]:
        """Normalize each cell's text and split multi-value cells into chunks.

        Yields ``(original_record, [chunk, ...])`` pairs. The original record
        carries the location and row_context; the chunks are the normalised
        sub-values ready for recognition.
        """
        for record in records:
            chunks = normalise_cell(record.text)
            if chunks:
                yield record, chunks

    # ------------------------------------------------------------------
    # Stage 3: Recognize + Stage 4: Context-Boost (combined for cache efficiency)
    # ------------------------------------------------------------------

    @staticmethod
    def stage_recognize(
        transformed: Iterator[tuple[CellRecord, list[str]]],
    ) -> Iterator[Finding]:
        """Run all registered recognizers on each chunk and apply context boosting.

        Immediate masking: raw_value is used only for deduplication and is never
        stored or yielded. Findings carry only ``masked_value``.
        """
        seen: set[tuple[str, str]] = set()  # (entity_type, raw_value_hash) per file

        for record, chunks in transformed:
            column_entity = detect_column_entity(record.location.column)
            has_row_ctx = detect_row_density(record.row_context)

            for chunk in chunks:
                inline_labels = detect_inline_labels(chunk)

                # Run every registered + active recognizer
                for recognizer in RECOGNIZER_REGISTRY.active():
                    for match in recognizer.find(chunk):
                        # Immediate deduplication via raw_value (never stored long-term)
                        dedup_key = (match.entity_type, match.raw_value)
                        if dedup_key in seen:
                            continue
                        seen.add(dedup_key)

                        # Context-boosted confidence
                        confidence = boost_confidence(
                            match.confidence,
                            match.entity_type,
                            column_entity,
                            inline_labels,
                            column_name=record.location.column,
                            has_row_context=has_row_ctx,
                        )

                        # raw_value is discarded here — only masked_value survives
                        yield Finding(
                            entity_type=match.entity_type,
                            masked_value=match.masked_value,
                            confidence=confidence,
                            location=record.location,
                        )

                # Masked identifier detection (AADHAAR_MASKED, PAN_MASKED, etc.)
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
        """Run the complete pipeline for a single file.

        Safely catches permission errors, corrupt files, and format errors so
        that one bad file never crashes an enterprise scan.
        """
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
        """Thread-parallel scan (I/O-bound workloads)."""
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
        """Process-parallel scan (CPU-bound: Verhoeff + regex). Bypasses GIL."""
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


# ---------------------------------------------------------------------------
# Module-level picklable function for ProcessPoolExecutor (Windows spawn safe)
# ---------------------------------------------------------------------------

def _pipeline_scan_file(path: Path) -> list[Finding]:
    """Top-level picklable wrapper for Pipeline.scan_file().

    Must remain at module level (not nested) for Windows 'spawn' compatibility.
    """
    return list(Pipeline().scan_file(path))
