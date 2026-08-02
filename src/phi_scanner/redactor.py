"""Redaction and Sanitization Engine — produces PII-masked copies of files.

Processes CSV and Excel documents to replace identified PII data cells with
sanitised representation tokens (e.g. "[REDACTED_AADHAAR]" or "XXXX XXXX 1234"),
allowing organisations to safely share or store remediated data artifacts.
"""
from __future__ import annotations

import csv
from pathlib import Path
from typing import Sequence

import openpyxl

from .engine import Finding
from .recognizers.aadhaar import find_aadhaar
from .recognizers.gstin import find_gstin
from .recognizers.mobile import find_mobile
from .recognizers.pan import find_pan
from .recognizers.passport import find_passport
from .recognizers.voter_id import find_voter_id


def sanitize_text(text: str, mask_token: str | None = None) -> str:
    """Replace any detected PII tokens within a text string with sanitized masks."""
    if not text:
        return text

    sanitized = text

    # Redact Aadhaar
    for m in find_aadhaar(sanitized):
        replacement = mask_token or m.masked_value
        sanitized = sanitized.replace(m.raw_value, replacement)

    # Redact PAN
    for m in find_pan(sanitized):
        replacement = mask_token or m.masked_value
        sanitized = sanitized.replace(m.raw_value, replacement)

    # Redact GSTIN
    for m in find_gstin(sanitized):
        replacement = mask_token or m.masked_value
        sanitized = sanitized.replace(m.raw_value, replacement)

    # Redact Mobile
    for m in find_mobile(sanitized):
        replacement = mask_token or m.masked_value
        sanitized = sanitized.replace(m.raw_value, replacement)

    # Redact Voter ID
    for m in find_voter_id(sanitized):
        replacement = mask_token or m.masked_value
        sanitized = sanitized.replace(m.raw_value, replacement)

    # Redact Passport
    for m in find_passport(sanitized):
        replacement = mask_token or m.masked_value
        sanitized = sanitized.replace(m.raw_value, replacement)

    return sanitized


def redact_csv(input_path: Path, output_path: Path, mask_token: str | None = None) -> int:
    """Redact PII in a CSV file and save to output_path. Returns count of redacted cells."""
    redacted_count = 0
    rows = []

    with open(input_path, "r", encoding="utf-8-sig", newline="") as f:
        reader = csv.reader(f)
        for row in reader:
            new_row = []
            for cell in row:
                sanitized = sanitize_text(str(cell), mask_token=mask_token)
                if sanitized != cell:
                    redacted_count += 1
                new_row.append(sanitized)
            rows.append(new_row)

    output_path.parent.mkdir(parents=True, exist_ok=True)
    with open(output_path, "w", encoding="utf-8", newline="") as f:
        writer = csv.writer(f)
        writer.writerows(rows)

    return redacted_count


def redact_xlsx(input_path: Path, output_path: Path, mask_token: str | None = None) -> int:
    """Redact PII in an Excel (.xlsx) workbook and save to output_path."""
    redacted_count = 0
    wb = openpyxl.load_workbook(input_path)

    for sheet in wb.worksheets:
        for row in sheet.iter_rows():
            for cell in row:
                if cell.value is not None:
                    val_str = str(cell.value)
                    sanitized = sanitize_text(val_str, mask_token=mask_token)
                    if sanitized != val_str:
                        cell.value = sanitized
                        redacted_count += 1

    output_path.parent.mkdir(parents=True, exist_ok=True)
    wb.save(output_path)
    wb.close()
    return redacted_count


def redact_file(input_path: Path, output_path: Path, mask_token: str | None = None) -> int:
    """Redact PII in input_path (.csv or .xlsx) and write to output_path."""
    suffix = input_path.suffix.lower()
    if suffix == ".csv":
        return redact_csv(input_path, output_path, mask_token=mask_token)
    elif suffix in (".xlsx", ".xls"):
        return redact_xlsx(input_path, output_path, mask_token=mask_token)
    else:
        raise ValueError(f"Unsupported file format for redaction: {suffix}")
