"""Ingestion layer — format-specific parsers that yield (text, SourceLocation)."""
from .base import Ingester, SourceLocation
from .csv_ingester import CsvIngester
from .xlsx_ingester import XlsxIngester

__all__ = ["CsvIngester", "XlsxIngester", "Ingester", "SourceLocation"]
