"""Tests for Indian Passport recognizer."""
from phi_scanner.recognizers.passport import find_passport, Confidence


def test_passport_valid() -> None:
    text = "Holder Passport No. A1234567 and Z9876543"
    matches = find_passport(text)
    assert len(matches) == 2
    assert matches[0].raw_value == "A1234567"
    assert matches[0].masked_value == "AXXXX567"
    assert matches[0].confidence == Confidence.MEDIUM


def test_passport_invalid() -> None:
    # O, Q, X are invalid first letters in Indian passport numbering
    text = "O1234567 or Q1234567 or X1234567 or 11234567"
    matches = find_passport(text)
    assert len(matches) == 0
