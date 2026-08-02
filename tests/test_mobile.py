"""Tests for the mobile number recognizer."""
import pytest

from phi_scanner.recognizers.mobile import Confidence, find_mobile
from tests.corpus.mobile_corpus import (
    HARD_NEGATIVES,
    TRUE_POSITIVES,
    TRUE_POSITIVE_VARIANTS,
)


class TestMobileTruePositives:
    @pytest.mark.parametrize("number", TRUE_POSITIVES)
    def test_bare_number_detected(self, number: str) -> None:
        matches = find_mobile(number)
        assert len(matches) >= 1, f"No match for {number!r}"

    @pytest.mark.parametrize("text", TRUE_POSITIVE_VARIANTS)
    def test_variant_formats_detected(self, text: str) -> None:
        matches = find_mobile(text)
        assert len(matches) >= 1, f"No match in {text!r}"

    def test_confidence_is_always_medium(self) -> None:
        # No checksum available — confidence must never be HIGH (rules.md §10)
        for number in TRUE_POSITIVES:
            for match in find_mobile(number):
                assert match.confidence == Confidence.MEDIUM, (
                    f"Mobile match for {number!r} was {match.confidence}, expected MEDIUM"
                )

    def test_country_code_stripped_from_normalised(self) -> None:
        matches = find_mobile("+91 9876543210")
        assert len(matches) >= 1
        assert matches[0].normalised == "9876543210"

    def test_masked_value_format(self) -> None:
        matches = find_mobile("9876543210")
        assert matches[0].masked_value == "XXXXXX3210"


class TestMobileHardNegatives:
    @pytest.mark.parametrize("case", HARD_NEGATIVES)
    def test_hard_negative_not_detected(self, case: dict) -> None:
        matches = find_mobile(case["value"])
        assert len(matches) == 0, (
            f"Unexpected match for reason={case['reason']!r}, "
            f"value={case['value']!r}: {matches}"
        )

    def test_starts_with_5_not_detected(self) -> None:
        assert find_mobile("5876543210") == []

    def test_nine_digit_not_detected(self) -> None:
        assert find_mobile("987654321") == []


class TestMobilePrecisionRecall:
    def test_recall_on_true_positives(self) -> None:
        tp = sum(1 for n in TRUE_POSITIVES if find_mobile(n))
        assert tp / len(TRUE_POSITIVES) == 1.0

    def test_no_fp_on_hard_negatives(self) -> None:
        fp = sum(1 for c in HARD_NEGATIVES if find_mobile(c["value"]))
        assert fp == 0
