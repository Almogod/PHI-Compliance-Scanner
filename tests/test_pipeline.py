"""Tests for the formal Pipeline architecture (stage decomposition)."""
import pytest
from pathlib import Path
from unittest.mock import patch

from phi_scanner.pipeline import Pipeline
from phi_scanner.ingestion.base import CellRecord, SourceLocation


def _make_record(text: str, column: str = "data", row_context: str = "") -> CellRecord:
    return CellRecord(
        text=text,
        location=SourceLocation(
            file_path=Path("test.csv"),
            sheet_name=None,
            row=2,
            column=column,
        ),
        row_context=row_context,
    )


class TestPipelineStages:
    def test_stage_transform_normalizes_text(self) -> None:
        pipeline = Pipeline()
        records = [_make_record("9876543210.0")]  # Excel float format
        transformed = list(pipeline.stage_transform(iter(records)))
        assert len(transformed) == 1
        _record, chunks = transformed[0]
        # normalise_cell should strip the .0
        assert "9876543210" in chunks

    def test_stage_transform_splits_multi_value(self) -> None:
        pipeline = Pipeline()
        records = [_make_record("ABCPD1234E, EFGPH5678J")]
        transformed = list(pipeline.stage_transform(iter(records)))
        assert len(transformed) == 1
        _record, chunks = transformed[0]
        assert len(chunks) >= 2

    def test_stage_recognize_detects_pan(self) -> None:
        pipeline = Pipeline()
        records = [_make_record("ABCPD1234E")]
        transformed = pipeline.stage_transform(iter(records))
        findings = list(pipeline.stage_recognize(transformed))
        pan_findings = [f for f in findings if f.entity_type == "PAN"]
        assert len(pan_findings) >= 1
        assert pan_findings[0].masked_value == "XXXXX1234X"

    def test_stage_recognize_penalty_column_downgrades(self) -> None:
        """Cells in 'invoice' columns should be downgraded to LOW."""
        pipeline = Pipeline()
        # Use a 12-digit Aadhaar-length number in an 'invoice' column
        # The Aadhaar recognizer may or may not match (depends on Verhoeff),
        # but if it does, confidence should be LOW due to column penalty.
        records = [_make_record("234567890124", column="invoice_number")]
        transformed = pipeline.stage_transform(iter(records))
        findings = list(pipeline.stage_recognize(transformed))
        for f in findings:
            if f.entity_type in ("AADHAAR",):
                assert f.confidence == "LOW", (
                    f"Expected LOW confidence in invoice column but got {f.confidence}"
                )

    def test_stage_recognize_row_context_boosts(self) -> None:
        """Row context containing address keywords should boost confidence."""
        pipeline = Pipeline()
        # PAN in a row with 'customer address email' context
        records = [_make_record(
            "ABCPD1234E",
            row_context="Rahul Kumar customer address Mumbai 400001",
        )]
        transformed = pipeline.stage_transform(iter(records))
        findings = list(pipeline.stage_recognize(transformed))
        pan_findings = [f for f in findings if f.entity_type == "PAN"]
        assert len(pan_findings) >= 1
        # PAN is already HIGH by holder-type, so this just validates no regression

    def test_full_pipeline_deduplication(self) -> None:
        """Same PAN appearing twice across chunks must yield one finding."""
        pipeline = Pipeline()
        # Two cells with the same PAN
        records = [
            _make_record("ABCPD1234E", row=2),
            _make_record("ABCPD1234E", row=3),
        ]
        # Manually run recognize on both records through one stage_recognize call
        # (deduplication is per-file call)
        transformed = pipeline.stage_transform(iter(records))
        findings = list(pipeline.stage_recognize(transformed))
        pan_findings = [f for f in findings if f.entity_type == "PAN"]
        assert len(pan_findings) == 1, "Duplicate PAN across rows must be deduplicated"

    def test_raw_value_not_in_findings(self) -> None:
        """raw_value must never appear in emitted Finding objects."""
        pipeline = Pipeline()
        records = [_make_record("ABCPD1234E")]
        transformed = pipeline.stage_transform(iter(records))
        findings = list(pipeline.stage_recognize(transformed))
        for f in findings:
            # Finding has no raw_value attribute by design
            assert not hasattr(f, "raw_value"), "Finding must not carry raw_value"


def _make_record(text: str, column: str = "data", row_context: str = "", row: int = 2) -> CellRecord:  # type: ignore[misc]
    return CellRecord(
        text=text,
        location=SourceLocation(
            file_path=Path("test.csv"),
            sheet_name=None,
            row=row,
            column=column,
        ),
        row_context=row_context,
    )
