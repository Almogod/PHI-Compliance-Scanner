"""Scan engine — orchestrates ingestion → normalisation → recognition → context boosting.

v4.0 Architecture:
  Delegates scan execution directly to the formal Pipeline class (``pipeline.py``),
  ensuring zero code duplication, dynamic auto-registration of recognizers via
  RECOGNIZER_REGISTRY, and lazy generator streaming end-to-end.

No network calls are made in this module or anything it imports.
Scanned content exists in memory only for the duration of the scan and is not
persisted anywhere except the report the caller explicitly writes.
"""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Iterator

from .ingestion.base import SourceLocation  # noqa: F401 — re-exported & used in location model

if TYPE_CHECKING:
    from .pipeline import Pipeline


# ---------------------------------------------------------------------------
# Finding dataclass (defined first so pipeline.py can import it)
# ---------------------------------------------------------------------------

@dataclass(frozen=True, slots=True)
class Finding:
    """One detected identifier instance with its full provenance."""

    entity_type: str       # "AADHAAR" | "PAN" | "GSTIN" | "IN_MOBILE" | "BANK_ACCOUNT" | "IFSC" | "*_MASKED"
    masked_value: str      # value with sensitive digits/chars redacted
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
# Engine (delegates to Pipeline)
# ---------------------------------------------------------------------------

class ScanEngine:
    """Walks a file or directory tree, scans every supported file, and yields
    ``Finding`` objects.

    Uses formal generator-based ``Pipeline`` underneath.
    """

    def __init__(self) -> None:
        from .pipeline import Pipeline
        self._pipeline = Pipeline()

    def scan_file(self, path: Path) -> Iterator[Finding]:
        """Yield findings from a single file via Pipeline."""
        yield from self._pipeline.scan_file(path)

    def scan_path(self, path: Path) -> Iterator[Finding]:
        """Recursively scan a file or directory via Pipeline."""
        yield from self._pipeline.scan_path(path)

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
        yield from self._pipeline.scan_path_parallel(path, max_workers=max_workers)

    def scan_path_processes(
        self, path: Path, max_workers: int = 4
    ) -> Iterator[Finding]:
        """CPU-parallel directory scan using ProcessPoolExecutor (bypasses GIL)."""
        yield from self._pipeline.scan_path_processes(path, max_workers=max_workers)


# Top-level picklable wrapper for ProcessPoolExecutor (Windows compatibility)
def _scan_file_process(path: Path) -> list[Finding]:
    """Top-level picklable wrapper for ScanEngine.scan_file()."""
    return list(ScanEngine().scan_file(path))
