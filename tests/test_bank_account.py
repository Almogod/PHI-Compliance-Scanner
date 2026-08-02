"""Tests for Bank Account + IFSC recognizer."""
import pytest

from phi_scanner.recognizers.bank_account import BankAccountRecognizer


@pytest.fixture
def rec() -> BankAccountRecognizer:
    return BankAccountRecognizer()


class TestIfscDetection:
    def test_known_bank_ifsc_is_medium(self, rec: BankAccountRecognizer) -> None:
        matches = rec.find("IFSC: HDFC0001234")
        ifsc_matches = [m for m in matches if m.entity_type == "IFSC"]
        assert len(ifsc_matches) == 1
        assert ifsc_matches[0].confidence == "MEDIUM"
        assert ifsc_matches[0].extra is not None
        assert ifsc_matches[0].extra["bank_code"] == "HDFC"

    def test_sbi_ifsc_detected(self, rec: BankAccountRecognizer) -> None:
        matches = rec.find("Account IFSC: SBIN0012345")
        ifsc_matches = [m for m in matches if m.entity_type == "IFSC"]
        assert len(ifsc_matches) >= 1
        assert ifsc_matches[0].confidence == "MEDIUM"

    def test_unknown_bank_ifsc_is_low(self, rec: BankAccountRecognizer) -> None:
        # ZZZZ is not a known bank code
        matches = rec.find("ZZZZ0ABCDEF")
        ifsc_matches = [m for m in matches if m.entity_type == "IFSC"]
        assert len(ifsc_matches) == 1
        assert ifsc_matches[0].confidence == "LOW"

    def test_ifsc_masked_correctly(self, rec: BankAccountRecognizer) -> None:
        matches = rec.find("HDFC0001234")
        ifsc_matches = [m for m in matches if m.entity_type == "IFSC"]
        assert len(ifsc_matches) == 1
        # Should expose bank code, mask branch
        assert ifsc_matches[0].masked_value.startswith("HDFC")
        assert "XXXXXX" in ifsc_matches[0].masked_value

    def test_no_ifsc_in_plain_text(self, rec: BankAccountRecognizer) -> None:
        matches = rec.find("Hello World 12345")
        ifsc_matches = [m for m in matches if m.entity_type == "IFSC"]
        assert len(ifsc_matches) == 0


class TestBankAccountDetection:
    def test_11_digit_account_detected(self, rec: BankAccountRecognizer) -> None:
        matches = rec.find("Account No: 12345678901")
        acct_matches = [m for m in matches if m.entity_type == "BANK_ACCOUNT"]
        assert len(acct_matches) >= 1

    def test_account_masked_shows_last_4(self, rec: BankAccountRecognizer) -> None:
        matches = rec.find("12345678901")
        acct_matches = [m for m in matches if m.entity_type == "BANK_ACCOUNT"]
        assert len(acct_matches) >= 1
        assert acct_matches[0].masked_value.endswith("8901")
        assert "XXXXXXX" in acct_matches[0].masked_value

    def test_account_starting_with_zero_rejected(self, rec: BankAccountRecognizer) -> None:
        # Bank accounts never start with 0
        matches = rec.find("01234567890")
        acct_matches = [m for m in matches if m.entity_type == "BANK_ACCOUNT"]
        assert len(acct_matches) == 0

    def test_account_confidence_is_low_without_context(self, rec: BankAccountRecognizer) -> None:
        matches = rec.find("12345678901")
        acct_matches = [m for m in matches if m.entity_type == "BANK_ACCOUNT"]
        assert all(m.confidence == "LOW" for m in acct_matches)
