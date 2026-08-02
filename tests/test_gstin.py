"""Tests for the GSTIN recognizer and checksum algorithm."""
import pytest

from phi_scanner.recognizers.gstin import (
    Confidence,
    _gstin_check_digit,
    find_gstin,
    validate_gstin,
)
from tests.corpus.gstin_corpus import (
    HARD_NEGATIVES,
    TRUE_POSITIVES,
    TRUE_POSITIVE_VARIANTS,
)


class TestGstinChecksum:
    def test_known_valid_gstin(self) -> None:
        # Publicly documented: 27AAPFU0939F1ZV
        assert validate_gstin("27AAPFU0939F1ZV")

    def test_check_digit_round_trip(self) -> None:
        prefix = "29ABCPD1234E1Z"
        digit = _gstin_check_digit(prefix)
        assert validate_gstin(prefix + digit)

    def test_wrong_check_digit_fails(self) -> None:
        assert not validate_gstin("27AAPFU0939F1ZW")  # should be V


class TestGstinTruePositives:
    @pytest.mark.parametrize("gstin", TRUE_POSITIVES)
    def test_valid_gstin_detected_as_high(self, gstin: str) -> None:
        matches = find_gstin(gstin)
        assert len(matches) >= 1, f"No match for {gstin!r}"
        assert matches[0].confidence == Confidence.HIGH

    @pytest.mark.parametrize("text", TRUE_POSITIVE_VARIANTS)
    def test_variant_formats_detected(self, text: str) -> None:
        matches = find_gstin(text)
        assert len(matches) >= 1, f"No match in {text!r}"

    def test_masked_value_hides_middle(self) -> None:
        matches = find_gstin("27AAPFU0939F1ZV")
        assert matches[0].masked_value.startswith("27")
        assert "XXXXXXXXXX" in matches[0].masked_value


class TestGstinHardNegatives:
    @pytest.mark.parametrize("case", HARD_NEGATIVES)
    def test_hard_negative_not_high(self, case: dict) -> None:
        matches = find_gstin(case["value"])
        high = [m for m in matches if m.confidence == Confidence.HIGH]
        assert len(high) == 0, (
            f"Unexpected HIGH for reason={case['reason']!r}, value={case['value']!r}"
        )

    def test_invalid_state_code_is_low(self) -> None:
        from phi_scanner.recognizers.gstin import _gstin_check_digit
        # State 00 is invalid
        gstin = "00ABCPD1234E1Z" + _gstin_check_digit("00ABCPD1234E1Z")
        matches = find_gstin(gstin)
        assert all(m.confidence == Confidence.LOW for m in matches)


class TestGstinPrecisionRecall:
    def test_precision_on_true_positives(self) -> None:
        tp = sum(1 for g in TRUE_POSITIVES if find_gstin(g))
        assert tp / len(TRUE_POSITIVES) == 1.0

    def test_no_high_fp_on_hard_negatives(self) -> None:
        fp = sum(
            1 for c in HARD_NEGATIVES
            if any(m.confidence == Confidence.HIGH for m in find_gstin(c["value"]))
        )
        assert fp == 0
