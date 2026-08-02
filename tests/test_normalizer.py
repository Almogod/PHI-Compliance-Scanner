"""Tests for the normalizer module."""
from phi_scanner.normalizer import (
    normalise_cell,
    normalise_excel_number,
    normalise_unicode,
    split_multi_value_cell,
)


class TestNormaliseUnicode:
    def test_strips_zero_width_characters(self) -> None:
        text = "ABCPD\u200b1234E"  # zero-width space inside PAN
        assert "\u200b" not in normalise_unicode(text)

    def test_normalises_nonbreaking_space(self) -> None:
        text = "2345\u00a06789\u00a00124"  # non-breaking spaces
        result = normalise_unicode(text)
        assert "\u00a0" not in result
        assert " " in result

    def test_smart_quotes_to_straight(self) -> None:
        assert normalise_unicode("\u201cPAN\u201d") == '"PAN"'

    def test_nfkc_normalisation(self) -> None:
        # Full-width digits → ASCII
        assert normalise_unicode("\uff19\uff18\uff17\uff16") == "9876"


class TestNormaliseExcelNumber:
    def test_trailing_dot_zero_stripped(self) -> None:
        assert normalise_excel_number("9876543210.0") == "9876543210"

    def test_decimal_preserved(self) -> None:
        assert normalise_excel_number("123.45") == "123.45"

    def test_integer_string_unchanged(self) -> None:
        assert normalise_excel_number("9876543210") == "9876543210"

    def test_multiple_dot_zero_only_last_stripped(self) -> None:
        assert normalise_excel_number("1.0.0") == "1.0.0"


class TestSplitMultiValueCell:
    def test_single_value_returns_one_chunk(self) -> None:
        result = split_multi_value_cell("9876543210")
        assert result == ["9876543210"]

    def test_comma_separated_splits(self) -> None:
        result = split_multi_value_cell("PAN: ABCPD1234E, Mobile: 9876543210")
        assert len(result) > 1
        assert "PAN: ABCPD1234E" in result
        assert "Mobile: 9876543210" in result

    def test_semicolon_separated_splits(self) -> None:
        result = split_multi_value_cell("ABCPD1234E; 27AAPFU0939F1ZV")
        assert len(result) > 1

    def test_pipe_separated_splits(self) -> None:
        result = split_multi_value_cell("value1|value2")
        assert len(result) > 1

    def test_short_fragments_dropped(self) -> None:
        # Fragments < 5 chars are not worth scanning individually
        result = split_multi_value_cell("ABCPD1234E, AB")
        assert "AB" not in result


class TestNormaliseCellPipeline:
    def test_full_pipeline_excel_float(self) -> None:
        chunks = normalise_cell("9876543210.0")
        assert "9876543210" in chunks[0]

    def test_full_pipeline_multi_value(self) -> None:
        chunks = normalise_cell("PAN: ABCPD1234E, UID: 234567890124")
        assert len(chunks) > 1

    def test_full_pipeline_unicode_cleanup(self) -> None:
        chunks = normalise_cell("ABCPD\u200b1234E")
        assert "\u200b" not in chunks[0]
