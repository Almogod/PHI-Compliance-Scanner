"""Tests for the PAN recognizer."""
import pytest

from phi_scanner.recognizers.pan import Confidence, find_pan
from tests.corpus.pan_corpus import (
    HARD_NEGATIVES,
    TRUE_POSITIVES,
    TRUE_POSITIVE_VARIANTS,
)


class TestPanTruePositives:
    @pytest.mark.parametrize("case", TRUE_POSITIVES)
    def test_valid_pan_detected_as_high(self, case: dict) -> None:
        matches = find_pan(case["value"])
        assert len(matches) >= 1, f"No match for {case['value']!r}"
        assert matches[0].confidence == Confidence.HIGH

    @pytest.mark.parametrize("text", TRUE_POSITIVE_VARIANTS)
    def test_variant_formats_detected(self, text: str) -> None:
        matches = find_pan(text)
        assert len(matches) >= 1, f"No match found in: {text!r}"

    def test_holder_type_label_returned(self) -> None:
        matches = find_pan("ABCPD1234E")
        assert matches[0].holder_type == "Individual"

    def test_masked_value_format(self) -> None:
        matches = find_pan("ABCPD1234E")
        assert matches[0].masked_value == "XXXXX1234X"


class TestPanHardNegatives:
    @pytest.mark.parametrize("case", HARD_NEGATIVES)
    def test_hard_negative_not_high_confidence(self, case: dict) -> None:
        matches = find_pan(case["value"])
        high = [m for m in matches if m.confidence == Confidence.HIGH]
        assert len(high) == 0, (
            f"Unexpected HIGH match for reason={case['reason']!r}, "
            f"value={case['value']!r}"
        )

    def test_nine_char_string_not_detected(self) -> None:
        assert find_pan("ABCPD123E") == []

    def test_invalid_holder_type_is_medium_not_high(self) -> None:
        # 'D' is not a valid holder-type code → MEDIUM
        matches = find_pan("ABCDD1234E")
        assert all(m.confidence == Confidence.MEDIUM for m in matches)

    def test_invalid_z_and_q_dropped(self) -> None:
        # 4th char Z or Q are invalid status codes and must be dropped immediately
        assert find_pan("ABCZD1234E") == []
        assert find_pan("ABCQD1234E") == []



class TestPanPrecisionRecall:
    def test_precision_on_true_positives(self) -> None:
        unique = list({c["value"] for c in TRUE_POSITIVES})
        tp = sum(1 for v in unique if find_pan(v))
        assert tp / len(unique) == 1.0

    def test_no_high_fp_on_hard_negatives(self) -> None:
        fp = sum(
            1 for c in HARD_NEGATIVES
            if any(m.confidence == Confidence.HIGH for m in find_pan(c["value"]))
        )
        assert fp == 0
