"""Scan engine — orchestrates ingestion → recognition → confidence tiering.

No network calls are made in this module or anything it imports.
Scanned content exists in memory only for the duration of the scan and is not
persisted anywhere except the report the caller explicitly writes.
"""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Iterator

from .ingestion.base import SourceLocation
from .ingestion.csv_ingester import CsvIngester
from .ingestion.xlsx_ingester import XlsxIngester
from .recognizers.aadhaar import find_aadhaar
from .recognizers.pan import find_pan
from .recognizers.gstin import find_gstin
from .recognizers.mobile import find_mobile

# ---------------------------------------------------------------------------
# Finding dataclass
# ---------------------------------------------------------------------------

@dataclass(frozen=True, slots=True)
class Finding:
    """One detected identifier instance with its full provenance."""

    entity_type: str       # "AADHAAR" | "PAN" | "GSTIN" | "IN_MOBILE"
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
    ".xls": XlsxIngester(),  # openpyxl can read legacy xls via compatibility
}


class ScanEngine:
    """Walks a file or directory tree, scans every supported file, and yields
    ``Finding`` objects.

    Architecture note (architecture.md §2): recognizers are called directly
    here without going through Presidio's full ``AnalyzerEngine`` because v1
    is pattern-only (no spaCy NLP). The recognizer classes are written as
    standalone functions that are trivially composable with Presidio's
    ``PatternRecognizer`` base if/when the NLP pipeline is enabled in Phase 3.
    """

    def scan_file(self, path: Path) -> Iterator[Finding]:
        """Yield findings from a single file."""
        suffix = path.suffix.lower()
        ingester = _INGESTERS.get(suffix)
        if ingester is None:
            return  # unsupported format — silently skip (v1 is CSV/XLSX only)

        for cell_text, location in ingester.ingest(path):
            yield from self._apply_recognizers(cell_text, location)

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

    # ------------------------------------------------------------------

    def _apply_recognizers(
        self, text: str, location: SourceLocation
    ) -> Iterator[Finding]:
        for match in find_aadhaar(text):
            yield Finding("AADHAAR", match.masked_value, match.confidence.value, location)

        for match in find_pan(text):
            yield Finding("PAN", match.masked_value, match.confidence.value, location)

        for match in find_gstin(text):
            yield Finding("GSTIN", match.masked_value, match.confidence.value, location)

        for match in find_mobile(text):
            yield Finding("IN_MOBILE", match.masked_value, match.confidence.value, location)
