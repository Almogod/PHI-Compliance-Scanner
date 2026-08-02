"""Redaction and Sanitization Engine — produces PII-masked copies of files.

Processes CSV and Excel documents to replace identified PII data cells with
sanitised representation tokens (e.g. "[REDACTED_AADHAAR]" or "XXXX XXXX 1234"),
allowing organisations to safely share or store remediated data artifacts.

Design notes:
  - sanitize_text collects ALL replacements first (sorted by position, longest-match
    priority) and then applies them in a single reverse-offset pass. This avoids the
    cascade-replacement bug where an earlier replacement shifts string offsets and
    corrupts subsequent matches.
  - redact_csv skips None/empty cells entirely so no "None" string artefacts appear
    in the sanitised output.
  - redact_xlsx raises a clear ValueError for .xls files since openpyxl only supports
    the .xlsx format; callers should pre-validate or convert .xls files first.
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
    """Replace any detected PII tokens within a text string with sanitized masks.

    Collects all (start, end, replacement) spans from every recognizer first,
    then applies them in a single reverse-offset pass so earlier replacements
    cannot shift the string offsets of later replacements (cascade-replace bug fix).

    Overlapping spans are resolved by taking the longer (more specific) match.
    """
    if not text or not text.strip():
        return text

    # --- collect all replacement spans ---
    spans: list[tuple[int, int, str]] = []  # (start, end, replacement)

    # Each recognizer returns matches with start/end positions in its scanned string.
    # Because passport and voter_id normalise to uppercase internally, we must scan
    # the original text with the other recognizers and uppercase-normalised text for
    # those two. However for redaction we use raw_value to locate text accurately.
    # All recognizers except passport/voter_id operate on the original string.

    for m in find_aadhaar(text):
        replacement = mask_token or m.masked_value
        start = text.find(m.raw_value)
        if start != -1:
            spans.append((start, start + len(m.raw_value), replacement))

    for m in find_pan(text):
        replacement = mask_token or m.masked_value
        start = text.upper().find(m.raw_value)
        if start != -1:
            spans.append((start, start + len(m.raw_value), replacement))

    for m in find_gstin(text):
        replacement = mask_token or m.masked_value
        start = text.upper().find(m.raw_value)
        if start != -1:
            spans.append((start, start + len(m.raw_value), replacement))

    for m in find_mobile(text):
        # raw_value may include country-code prefix — search in stripped version;
        # fall back to normalised 10-digit form for plain matches
        start = text.find(m.raw_value)
        if start == -1:
            start = text.find(m.normalised)
            if start != -1:
                spans.append((start, start + len(m.normalised), mask_token or m.masked_value))
        else:
            spans.append((start, start + len(m.raw_value), mask_token or m.masked_value))

    upper = text.upper()
    for m in find_voter_id(text):
        replacement = mask_token or m.masked_value
        start = upper.find(m.raw_value)
        if start != -1:
            spans.append((start, start + len(m.raw_value), replacement))

    for m in find_passport(text):
        replacement = mask_token or m.masked_value
        start = upper.find(m.raw_value)
        if start != -1:
            spans.append((start, start + len(m.raw_value), replacement))

    if not spans:
        return text

    # --- resolve overlaps: keep longest span; sort by start then length desc ---
    spans.sort(key=lambda s: (s[0], -(s[1] - s[0])))
    resolved: list[tuple[int, int, str]] = []
    last_end = -1
    for start, end, rep in spans:
        if start >= last_end:
            resolved.append((start, end, rep))
            last_end = end
        # else: overlapping/nested span — skip (the first/longer one wins)

    # --- apply replacements in reverse order (so offsets stay valid) ---
    result = text
    for start, end, rep in reversed(resolved):
        result = result[:start] + rep + result[end:]

    return result


def redact_csv(input_path: Path, output_path: Path, mask_token: str | None = None) -> int:
    """Redact PII in a CSV file and save to output_path. Returns count of redacted cells."""
    redacted_count = 0
    rows = []

    with open(input_path, "r", encoding="utf-8-sig", newline="") as f:
        reader = csv.reader(f)
        for row in reader:
            new_row = []
            for cell in row:
                # Guard: skip None or empty cells — don't stringify None to "None"
                if cell is None or not str(cell).strip():
                    new_row.append(cell)
                    continue
                cell_str = str(cell)
                sanitized = sanitize_text(cell_str, mask_token=mask_token)
                if sanitized != cell_str:
                    redacted_count += 1
                new_row.append(sanitized)
            rows.append(new_row)

    output_path.parent.mkdir(parents=True, exist_ok=True)
    with open(output_path, "w", encoding="utf-8", newline="") as f:
        writer = csv.writer(f)
        writer.writerows(rows)

    return redacted_count


def redact_xlsx(input_path: Path, output_path: Path, mask_token: str | None = None) -> int:
    """Redact PII in an Excel (.xlsx) workbook and save to output_path.

    Note: openpyxl only supports the .xlsx format. Passing a .xls file will raise
    a ValueError — callers should convert .xls to .xlsx before redacting.
    """
    suffix = input_path.suffix.lower()
    if suffix == ".xls":
        raise ValueError(
            f"openpyxl cannot read .xls (legacy Excel 97-2003) files. "
            f"Please convert '{input_path.name}' to .xlsx first."
        )

    redacted_count = 0
    wb = openpyxl.load_workbook(input_path)

    for sheet in wb.worksheets:
        for row in sheet.iter_rows():
            for cell in row:
                # Guard: skip None/empty cells — avoids writing the string "None"
                if cell.value is None:
                    continue
                val_str = str(cell.value)
                if not val_str.strip():
                    continue
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
        raise ValueError(f"Unsupported file format for redaction: {suffix!r}")
