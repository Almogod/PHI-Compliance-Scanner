"""Scan engine — orchestrates ingestion → normalisation → recognition → context boosting.

v2 improvements over v1:
  - Text normalisation (Excel floats, unicode cleanup, zero-width chars)
  - Multi-value cell splitting (cells with commas/semicolons get sub-scanned)
  - Context-aware confidence boosting (column headers, inline labels)
  - Partially-masked identifier detection (XXXX XXXX 1234 is still PII)
  - Header row extraction for column-level context signals

No network calls are made in this module or anything it imports.
Scanned content exists in memory only for the duration of the scan and is not
persisted anywhere except the report the caller explicitly writes.
"""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Iterator

from .ingestion.base import SourceLocation  # noqa: F401 — re-exported & used in scan_file error path

from .ingestion.csv_ingester import CsvIngester
from .ingestion.xlsx_ingester import XlsxIngester
from .ingestion.docx_ingester import DocxIngester
from .ingestion.pdf_ingester import PdfIngester
from .normalizer import normalise_cell
from .context import (
    boost_confidence,
    detect_column_entity,
    detect_inline_labels,
    detect_masked_identifiers,
)
from .recognizers.aadhaar import find_aadhaar
from .recognizers.pan import find_pan
from .recognizers.gstin import find_gstin
from .recognizers.mobile import find_mobile
from .recognizers.voter_id import find_voter_id
from .recognizers.passport import find_passport

# ---------------------------------------------------------------------------
# Finding dataclass
# ---------------------------------------------------------------------------

@dataclass(frozen=True, slots=True)
class Finding:
    """One detected identifier instance with its full provenance."""

    entity_type: str       # "AADHAAR" | "PAN" | "GSTIN" | "IN_MOBILE" | "*_MASKED"
    masked_value: str      # value with most digits/chars redacted
    confidence: str        # "HIGH" | "MEDIUM" | "LOW"
    location: SourceLocation

    def as_dict(self) -> dict[str, str]:
        d = self.location.as_dict()
        d.update({
            "entity_type": self.entity_type,
            "masked_value": self.masked_value,
            "confidence": self.confidence,
        })
        return d


# ---------------------------------------------------------------------------
# Engine
# ---------------------------------------------------------------------------

_INGESTERS: dict[str, object] = {
    ".csv": CsvIngester(),
    ".xlsx": XlsxIngester(),
    ".xls": XlsxIngester(),
    ".docx": DocxIngester(),
    ".pdf": PdfIngester(),
}


class ScanEngine:
    """Walks a file or directory tree, scans every supported file, and yields
    ``Finding`` objects.

    v2 scanning pipeline per cell:
      1. Normalise text (unicode, Excel floats)
      2. Split multi-value cells into sub-chunks
      3. Detect column-level context (header → entity type mapping)
      4. Detect inline labels ("PAN:", "Aadhaar No:", etc.)
      5. Run all recognizers on each chunk
      6. Boost confidence using context signals
      7. Detect partially-masked identifiers
      8. Yield all findings with boosted confidence
    """

    def scan_file(self, path: Path) -> Iterator[Finding]:
        """Yield findings from a single file.

        Safely catches permission locks, file corruption, and format errors
        so that a single bad file never crashes an entire enterprise scan.
        """
        suffix = path.suffix.lower()
        ingester = _INGESTERS.get(suffix)
        if ingester is None:
            return  # unsupported format — silently skip

        try:
            for cell_text, location in ingester.ingest(path):
                yield from self._scan_cell(cell_text, location)
        except Exception as exc:
            # Yield error diagnostic finding so auditors know this file was skipped.
            # Include class name + truncated message for root-cause visibility without leaking content.
            err_loc = SourceLocation(file_path=path, sheet_name=None, row=1, column="ERROR")
            yield Finding(
                entity_type="FILE_READ_ERROR",
                masked_value=f"{exc.__class__.__name__}: {str(exc)[:120]}",
                confidence="LOW",
                location=err_loc,
            )

    def scan_path(self, path: Path) -> Iterator[Finding]:
        """Recursively scan a file or all supported files under a directory."""
        if path.is_file():
            yield from self.scan_file(path)
        elif path.is_dir():
            for child in sorted(path.rglob("*")):
                if child.is_file() and child.suffix.lower() in _INGESTERS:
                    yield from self.scan_file(child)
        else:
            raise FileNotFoundError(f"Path does not exist: {path}")

    def scan_path_agents(self, path: Path, num_agents: int = 4) -> Iterator[Finding]:
        """Concurrent Agent Orchestration pipeline."""
        from .agent_orchestrator import ParallelAgentOrchestrator
        orchestrator = ParallelAgentOrchestrator(num_workers=num_agents)
        for af in orchestrator.orchestrate_path(path):
            yield Finding(
                entity_type=af.entity_type,
                masked_value=af.masked_value,
                confidence=af.confidence,
                location=af.location,
            )

    def scan_path_parallel(self, path: Path, max_workers: int = 4) -> Iterator[Finding]:
        """Parallel directory scan using thread workers for high throughput."""
        from concurrent.futures import ThreadPoolExecutor

        if path.is_file():
            yield from self.scan_file(path)
            return

        if not path.is_dir():
            raise FileNotFoundError(f"Path does not exist: {path}")

        files = [p for p in sorted(path.rglob("*")) if p.is_file() and p.suffix.lower() in _INGESTERS]
        if not files:
            return

        def _scan_one(f: Path) -> list[Finding]:
            return list(self.scan_file(f))

        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            for file_findings in executor.map(_scan_one, files):
                yield from file_findings

    # ------------------------------------------------------------------

    def _scan_cell(
        self, text: str, location: SourceLocation
    ) -> Iterator[Finding]:
        """Full v2 scanning pipeline for a single cell."""

        # Step 1+2: Normalise and split multi-value cells
        chunks = normalise_cell(text)

        # Step 3: Column-level context
        column_entity = detect_column_entity(location.column)

        # Deduplicate findings across chunks (original + sub-chunks).
        # Key on raw value so two identifiers that share last-4 digits are NOT collapsed.
        seen: set[tuple[str, str]] = set()  # (entity_type, raw_value)

        for chunk in chunks:
            # Step 4: Inline label context
            inline_labels = detect_inline_labels(chunk)

            # Step 5: Run all recognizers
            for match in find_aadhaar(chunk):
                key = ("AADHAAR", match.raw_value)
                if key in seen:
                    continue
                seen.add(key)

                # Step 6: Context-boosted confidence
                confidence = boost_confidence(
                    match.confidence.value, "AADHAAR",
                    column_entity, inline_labels,
                )
                yield Finding("AADHAAR", match.masked_value, confidence, location)

            for match in find_pan(chunk):
                key = ("PAN", match.raw_value)
                if key in seen:
                    continue
                seen.add(key)

                confidence = boost_confidence(
                    match.confidence.value, "PAN",
                    column_entity, inline_labels,
                )
                yield Finding("PAN", match.masked_value, confidence, location)

            for match in find_gstin(chunk):
                key = ("GSTIN", match.raw_value)
                if key in seen:
                    continue
                seen.add(key)

                confidence = boost_confidence(
                    match.confidence.value, "GSTIN",
                    column_entity, inline_labels,
                )
                yield Finding("GSTIN", match.masked_value, confidence, location)

            for match in find_mobile(chunk):
                key = ("IN_MOBILE", match.normalised)
                if key in seen:
                    continue
                seen.add(key)

                confidence = boost_confidence(
                    match.confidence.value, "IN_MOBILE",
                    column_entity, inline_labels,
                )
                yield Finding("IN_MOBILE", match.masked_value, confidence, location)

            for match in find_voter_id(chunk):
                key = ("VOTER_ID", match.raw_value)
                if key in seen:
                    continue
                seen.add(key)

                confidence = boost_confidence(
                    match.confidence.value, "VOTER_ID",
                    column_entity, inline_labels,
                )
                yield Finding("VOTER_ID", match.masked_value, confidence, location)

            for match in find_passport(chunk):
                key = ("PASSPORT", match.raw_value)
                if key in seen:
                    continue
                seen.add(key)

                confidence = boost_confidence(
                    match.confidence.value, "PASSPORT",
                    column_entity, inline_labels,
                )
                yield Finding("PASSPORT", match.masked_value, confidence, location)

            # Step 7: Detect partially-masked identifiers
            for masked in detect_masked_identifiers(chunk):
                key = (masked["entity_type"], masked["masked_value"])
                if key in seen:
                    continue
                seen.add(key)
                yield Finding(
                    masked["entity_type"],
                    masked["masked_value"],
                    masked["confidence"],
                    location,
                )
