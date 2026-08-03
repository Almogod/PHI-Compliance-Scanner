"""Redaction, Masking, and Tokenization Engine — produces PII-remediated copies of files.

Remediation modes:
  - "mask"    : Replaces sensitive digits with X / asterisks (e.g. "XXXX XXXX 1234")
  - "redact"  : Replaces sensitive values with explicit token (e.g. "[REDACTED_AADHAAR]")
  - "tokenize": Replaces sensitive values with deterministic HMAC-SHA256 tokens
                (e.g. "TOK-AADHAAR-8F3A29B1"), allowing secure cross-dataset correlation
                without exposing raw PII.

Supports CSV, Excel (.xlsx), and plain text documents.
"""
from __future__ import annotations

import csv
import hmac
import hashlib
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
from .recognizers.bank_account import find_bank_account, find_ifsc


def tokenize_value(raw_value: str, entity_type: str, salt: str = "PHI_COMPLIANCE_SALT") -> str:
    """Generate a deterministic, irreversible HMAC-SHA256 token for PII correlation."""
    digest = hmac.new(salt.encode("utf-8"), raw_value.encode("utf-8"), hashlib.sha256).hexdigest()[:8].upper()
    return f"TOK-{entity_type}-{digest}"


def sanitize_text(
    text: str,
    mask_token: str | None = None,
    mode: str = "mask",
    salt: str = "PHI_COMPLIANCE_SALT",
) -> str:
    """Remediate any detected PII tokens within a text string.

    Parameters
    ----------
    text:
        Input string to remediate.
    mask_token:
        Optional explicit replacement string override (e.g. "[REDACTED]").
    mode:
        Remediation mode: "mask" | "redact" | "tokenize".
    salt:
        Salt string used for HMAC-SHA256 token generation in "tokenize" mode.
    """
    if not text or not text.strip():
        return text

    spans: list[tuple[int, int, str]] = []  # (start, end, replacement)

    def _get_replacement(raw_val: str, masked_val: str, entity_type: str) -> str:
        if mask_token:
            return mask_token
        if mode == "tokenize":
            return tokenize_value(raw_val, entity_type, salt=salt)
        elif mode == "redact":
            return f"[REDACTED_{entity_type}]"
        else:  # mask
            return masked_val

    def _add_span(match_obj, entity_type: str):
        rep = _get_replacement(getattr(match_obj, "raw_value", getattr(match_obj, "normalised", str(match_obj))), match_obj.masked_value, entity_type)
        # Try finding formatted, raw_value, or normalised
        found_target = None
        for candidate in [getattr(match_obj, "formatted", None), getattr(match_obj, "raw_value", None), getattr(match_obj, "normalised", None)]:
            if candidate and candidate in text:
                found_target = candidate
                break
        if not found_target:
            # Try case-insensitive search
            upper_text = text.upper()
            for candidate in [getattr(match_obj, "formatted", None), getattr(match_obj, "raw_value", None), getattr(match_obj, "normalised", None)]:
                if candidate and candidate.upper() in upper_text:
                    found_target = candidate
                    break

        if found_target:
            start = text.find(found_target)
            if start == -1:
                start = text.upper().find(found_target.upper())
            if start != -1:
                spans.append((start, start + len(found_target), rep))

    # Collect spans from all active recognizers
    for m in find_aadhaar(text):
        _add_span(m, "AADHAAR")

    for m in find_pan(text):
        _add_span(m, "PAN")

    for m in find_gstin(text):
        _add_span(m, "GSTIN")

    for m in find_mobile(text):
        _add_span(m, "IN_MOBILE")

    for m in find_voter_id(text):
        _add_span(m, "VOTER_ID")

    for m in find_passport(text):
        _add_span(m, "PASSPORT")

    for m in find_bank_account(text):
        _add_span(m, "BANK_ACCOUNT")

    for m in find_ifsc(text):
        _add_span(m, "IFSC")

    if not spans:
        return text

    # Sort spans by start offset, longest match first
    spans.sort(key=lambda s: (s[0], -(s[1] - s[0])))
    resolved: list[tuple[int, int, str]] = []
    last_end = -1
    for start, end, rep in spans:
        if start >= last_end:
            resolved.append((start, end, rep))
            last_end = end

    result = text
    for start, end, rep in reversed(resolved):
        result = result[:start] + rep + result[end:]

    return result


def redact_csv(
    input_path: Path,
    output_path: Path,
    mask_token: str | None = None,
    mode: str = "mask",
    salt: str = "PHI_COMPLIANCE_SALT",
) -> int:
    """Remediate PII in a CSV file and save to output_path. Returns count of modified cells."""
    redacted_count = 0
    rows = []

    with open(input_path, "r", encoding="utf-8-sig", newline="") as f:
        reader = csv.reader(f)
        for row in reader:
            new_row = []
            for cell in row:
                if cell is None or not str(cell).strip():
                    new_row.append(cell)
                    continue
                cell_str = str(cell)
                sanitized = sanitize_text(cell_str, mask_token=mask_token, mode=mode, salt=salt)
                if sanitized != cell_str:
                    redacted_count += 1
                new_row.append(sanitized)
            rows.append(new_row)

    output_path.parent.mkdir(parents=True, exist_ok=True)
    with open(output_path, "w", encoding="utf-8", newline="") as f:
        writer = csv.writer(f)
        writer.writerows(rows)

    return redacted_count


def redact_xlsx(
    input_path: Path,
    output_path: Path,
    mask_token: str | None = None,
    mode: str = "mask",
    salt: str = "PHI_COMPLIANCE_SALT",
) -> int:
    """Remediate PII in an Excel (.xlsx) workbook and save to output_path."""
    suffix = input_path.suffix.lower()
    if suffix == ".xls":
        raise ValueError("openpyxl cannot read .xls files. Convert to .xlsx first.")

    redacted_count = 0
    wb = openpyxl.load_workbook(input_path)

    for sheet in wb.worksheets:
        for row in sheet.iter_rows():
            for cell in row:
                if cell.value is None:
                    continue
                val_str = str(cell.value)
                if not val_str.strip():
                    continue
                sanitized = sanitize_text(val_str, mask_token=mask_token, mode=mode, salt=salt)
                if sanitized != val_str:
                    cell.value = sanitized
                    redacted_count += 1

    output_path.parent.mkdir(parents=True, exist_ok=True)
    wb.save(output_path)
    wb.close()
    return redacted_count


def redact_file(
    input_path: Path,
    output_path: Path,
    mask_token: str | None = None,
    mode: str = "mask",
    salt: str = "PHI_COMPLIANCE_SALT",
) -> int:
    """Remediate PII in input_path (.csv or .xlsx) and write to output_path."""
    suffix = input_path.suffix.lower()
    if suffix == ".csv":
        return redact_csv(input_path, output_path, mask_token=mask_token, mode=mode, salt=salt)
    elif suffix in (".xlsx", ".xls"):
        return redact_xlsx(input_path, output_path, mask_token=mask_token, mode=mode, salt=salt)
    else:
        try:
            with open(input_path, "r", encoding="utf-8", errors="replace") as f:
                content = f.read()
            remediated = sanitize_text(content, mask_token=mask_token, mode=mode, salt=salt)
            output_path.parent.mkdir(parents=True, exist_ok=True)
            with open(output_path, "w", encoding="utf-8") as f:
                f.write(remediated)
            return 1 if remediated != content else 0
        except Exception as exc:
            raise ValueError(f"Unsupported file format for remediation: {suffix!r}") from exc
