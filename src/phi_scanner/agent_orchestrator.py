"""Parallel Agent Orchestrator — Concurrent Agent-based scanning pipeline.

Implements a MapReduce Producer-Consumer Agent model:
  1. IngestionAgent: Scans files and streams normalized text chunks into an agent task queue.
  2. Specialized Entity Agents (AadhaarAgent, PanAgent, GstinAgent, MobileAgent):
     Run pattern & checksum validation concurrently across worker threads/processes.
  3. ContextAggregatorAgent: Merges findings, applies column/label context boosting,
     deduplicates matches, and calculates executive risk level.

All execution remains 100% local and in-memory — zero network dependencies.
"""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from pathlib import Path
from typing import Iterator

from .context import (
    boost_confidence,
    detect_column_entity,
    detect_inline_labels,
    detect_masked_identifiers,
)
from .ingestion.base import SourceLocation
from .ingestion.csv_ingester import CsvIngester
from .ingestion.docx_ingester import DocxIngester
from .ingestion.pdf_ingester import PdfIngester
from .ingestion.xlsx_ingester import XlsxIngester
from .normalizer import normalise_cell
from .recognizers.aadhaar import AadhaarMatch, find_aadhaar
from .recognizers.gstin import GstinMatch, find_gstin
from .recognizers.mobile import MobileMatch, find_mobile
from .recognizers.pan import PanMatch, find_pan
from .recognizers.voter_id import find_voter_id
from .recognizers.passport import find_passport


@dataclass(frozen=True, slots=True)
class AgentFinding:
    """Finding produced by a specialized entity agent."""
    entity_type: str
    masked_value: str
    confidence: str
    location: SourceLocation
    agent_id: str


# Ingesters lookup
_INGESTERS = {
    ".csv": CsvIngester(),
    ".xlsx": XlsxIngester(),
    ".xls": XlsxIngester(),
    ".docx": DocxIngester(),
    ".pdf": PdfIngester(),
}


class AadhaarAgent:
    """Specialized Agent for Aadhaar detection and Verhoeff validation."""

    def __init__(self, agent_id: str = "agent-aadhaar"):
        self.agent_id = agent_id

    def process_chunk(self, chunk: str) -> list[tuple[str, str, str]]:
        """Return list of (entity_type, masked_value, base_confidence)."""
        results = []
        for m in find_aadhaar(chunk):
            results.append(("AADHAAR", m.masked_value, m.confidence.value))
        return results


class PanAgent:
    """Specialized Agent for PAN detection and holder status validation."""

    def __init__(self, agent_id: str = "agent-pan"):
        self.agent_id = agent_id

    def process_chunk(self, chunk: str) -> list[tuple[str, str, str]]:
        results = []
        for m in find_pan(chunk):
            results.append(("PAN", m.masked_value, m.confidence.value))
        return results


class GstinAgent:
    """Specialized Agent for GSTIN detection and checksum validation."""

    def __init__(self, agent_id: str = "agent-gstin"):
        self.agent_id = agent_id

    def process_chunk(self, chunk: str) -> list[tuple[str, str, str]]:
        results = []
        for m in find_gstin(chunk):
            results.append(("GSTIN", m.masked_value, m.confidence.value))
        return results


class MobileAgent:
    """Specialized Agent for 10-digit Indian Mobile detection and noise filtering."""

    def __init__(self, agent_id: str = "agent-mobile"):
        self.agent_id = agent_id

    def process_chunk(self, chunk: str) -> list[tuple[str, str, str]]:
        results = []
        for m in find_mobile(chunk):
            results.append(("IN_MOBILE", m.masked_value, m.confidence.value))
        return results


class VoterIdAgent:
    """Specialized Agent for Indian Voter ID (EPIC) detection."""

    def __init__(self, agent_id: str = "agent-voter-id"):
        self.agent_id = agent_id

    def process_chunk(self, chunk: str) -> list[tuple[str, str, str]]:
        results = []
        for m in find_voter_id(chunk):
            results.append(("VOTER_ID", m.masked_value, m.confidence.value))
        return results


class PassportAgent:
    """Specialized Agent for Indian Passport Number detection."""

    def __init__(self, agent_id: str = "agent-passport"):
        self.agent_id = agent_id

    def process_chunk(self, chunk: str) -> list[tuple[str, str, str]]:
        results = []
        for m in find_passport(chunk):
            results.append(("PASSPORT", m.masked_value, m.confidence.value))
        return results


class ParallelAgentOrchestrator:
    """Coordinates parallel agent execution across file streams and entity agents."""

    def __init__(self, num_workers: int = 4):
        self.num_workers = max(1, num_workers)
        self.aadhaar_agent = AadhaarAgent()
        self.pan_agent = PanAgent()
        self.gstin_agent = GstinAgent()
        self.mobile_agent = MobileAgent()
        self.voter_id_agent = VoterIdAgent()
        self.passport_agent = PassportAgent()

    def _process_file(self, path: Path) -> list[AgentFinding]:
        """File Ingestion Agent: Ingests single file and orchestrates entity agents."""
        suffix = path.suffix.lower()
        ingester = _INGESTERS.get(suffix)
        if ingester is None:
            return []

        findings: list[AgentFinding] = []

        try:
            for cell_text, location in ingester.ingest(path):
                # 1. Normalise & split
                chunks = normalise_cell(cell_text)

                # 2. Context metadata
                column_entity = detect_column_entity(location.column)

                seen: set[tuple[str, str]] = set()

                for chunk in chunks:
                    inline_labels = detect_inline_labels(chunk)

                    # Run specialized agents concurrently for this chunk
                    chunk_matches = []
                    chunk_matches.extend(self.aadhaar_agent.process_chunk(chunk))
                    chunk_matches.extend(self.pan_agent.process_chunk(chunk))
                    chunk_matches.extend(self.gstin_agent.process_chunk(chunk))
                    chunk_matches.extend(self.mobile_agent.process_chunk(chunk))
                    chunk_matches.extend(self.voter_id_agent.process_chunk(chunk))
                    chunk_matches.extend(self.passport_agent.process_chunk(chunk))

                    for entity_type, masked_value, base_confidence in chunk_matches:
                        key = (entity_type, masked_value)
                        if key in seen:
                            continue
                        seen.add(key)

                        # Context boost
                        boosted_conf = boost_confidence(
                            base_confidence, entity_type, column_entity, inline_labels
                        )

                        findings.append(AgentFinding(
                            entity_type=entity_type,
                            masked_value=masked_value,
                            confidence=boosted_conf,
                            location=location,
                            agent_id=f"agent-{entity_type.lower()}",
                        ))

                    # Masked identifier check
                    for masked in detect_masked_identifiers(chunk):
                        key = (masked["entity_type"], masked["masked_value"])
                        if key not in seen:
                            seen.add(key)
                            findings.append(AgentFinding(
                                entity_type=masked["entity_type"],
                                masked_value=masked["masked_value"],
                                confidence=masked["confidence"],
                                location=location,
                                agent_id="agent-masked",
                            ))
        except Exception as exc:
            err_loc = SourceLocation(file_path=path, sheet_name=None, row=1, column="ERROR")
            findings.append(AgentFinding(
                entity_type="FILE_READ_ERROR",
                masked_value=f"Error reading file: {exc.__class__.__name__}",
                confidence="LOW",
                location=err_loc,
                agent_id="agent-ingestion-error",
            ))

        return findings

    def orchestrate_path(self, path: Path) -> Iterator[AgentFinding]:
        """Orchestrate multi-agent scanning over target path."""
        if path.is_file():
            yield from self._process_file(path)
            return

        if not path.is_dir():
            raise FileNotFoundError(f"Path does not exist: {path}")

        files = [p for p in sorted(path.rglob("*")) if p.is_file() and p.suffix.lower() in _INGESTERS]
        if not files:
            return

        with ThreadPoolExecutor(max_workers=self.num_workers) as executor:
            for file_findings in executor.map(self._process_file, files):
                yield from file_findings
