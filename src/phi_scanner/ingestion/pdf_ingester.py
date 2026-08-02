"""PDF ingester — yields ``(page_text, SourceLocation)`` for text-based PDF documents.

Preserves exact location metadata:
- Page-level provenance: location sheet_name="Page N", column="page_text", row=page_number
"""
from __future__ import annotations

from pathlib import Path
from typing import Iterator

from pypdf import PdfReader

from .base import SourceLocation


class PdfIngester:
    """Reads PDF files using pypdf and yields page text with page-level location provenance."""

    def ingest(self, path: Path) -> Iterator[tuple[str, SourceLocation]]:
        reader = PdfReader(path)
        for page_idx, page in enumerate(reader.pages, start=1):
            text = page.extract_text()
            if text and text.strip():
                # Yield page text chunks (split by lines for finer granularity)
                for line_idx, line in enumerate(text.splitlines(), start=1):
                    cleaned = line.strip()
                    if cleaned:
                        yield cleaned, SourceLocation(
                            file_path=path,
                            sheet_name=f"Page {page_idx}",
                            row=line_idx,
                            column="line",
                        )
