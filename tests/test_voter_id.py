"""Tests for Indian Voter ID (EPIC) recognizer."""
from phi_scanner.recognizers.voter_id import find_voter_id, Confidence


def test_voter_id_valid() -> None:
    text = "User Voter ID is ZDB1234567 and ABC7654321"
    matches = find_voter_id(text)
    assert len(matches) == 2
    assert matches[0].raw_value == "ZDB1234567"
    assert matches[0].masked_value == "ZDBXXXX567"
    assert matches[0].confidence == Confidence.MEDIUM


def test_voter_id_invalid_length() -> None:
    text = "Invalid Voter ID ZDB123456 or ZDB12345678"
    matches = find_voter_id(text)
    assert len(matches) == 0
