"""Tests for the context module — column headers, labels, confidence boosting."""
from phi_scanner.context import (
    boost_confidence,
    detect_column_entity,
    detect_inline_labels,
    detect_masked_identifiers,
)


class TestDetectColumnEntity:
    def test_aadhaar_column(self) -> None:
        assert detect_column_entity("aadhaar_no") == "AADHAAR"
        assert detect_column_entity("Aadhaar Number") == "AADHAAR"
        assert detect_column_entity("AADHAR") == "AADHAAR"  # common misspelling
        assert detect_column_entity("uid") == "AADHAAR"

    def test_pan_column(self) -> None:
        assert detect_column_entity("PAN") == "PAN"
        assert detect_column_entity("pan_number") == "PAN"
        assert detect_column_entity("Permanent Account Number") == "PAN"

    def test_gstin_column(self) -> None:
        assert detect_column_entity("GSTIN") == "GSTIN"
        assert detect_column_entity("gst_no") == "GSTIN"
        assert detect_column_entity("GST Number") == "GSTIN"

    def test_mobile_column(self) -> None:
        assert detect_column_entity("mobile") == "IN_MOBILE"
        assert detect_column_entity("Phone No") == "IN_MOBILE"
        assert detect_column_entity("contact_number") == "IN_MOBILE"
        assert detect_column_entity("WhatsApp") == "IN_MOBILE"

    def test_unrelated_column(self) -> None:
        assert detect_column_entity("employee_id") is None
        assert detect_column_entity("department") is None
        assert detect_column_entity("name") is None


class TestDetectInlineLabels:
    def test_pan_label(self) -> None:
        labels = detect_inline_labels("PAN: ABCPD1234E")
        assert "PAN" in labels

    def test_aadhaar_label(self) -> None:
        labels = detect_inline_labels("Aadhaar No. 234567890124")
        assert "AADHAAR" in labels

    def test_multiple_labels(self) -> None:
        labels = detect_inline_labels("PAN: ABCPD1234E, GST: 27AAPFU0939F1ZV")
        assert "PAN" in labels
        assert "GSTIN" in labels

    def test_no_label(self) -> None:
        labels = detect_inline_labels("9876543210")
        assert len(labels) == 0


class TestDetectMaskedIdentifiers:
    def test_masked_aadhaar_xxxx(self) -> None:
        result = detect_masked_identifiers("XXXX XXXX 1234")
        assert len(result) >= 1
        assert result[0]["entity_type"] == "AADHAAR_MASKED"

    def test_masked_aadhaar_stars(self) -> None:
        result = detect_masked_identifiers("**** **** 5678")
        assert len(result) >= 1
        assert result[0]["entity_type"] == "AADHAAR_MASKED"

    def test_no_false_masked(self) -> None:
        result = detect_masked_identifiers("ABCPD1234E")
        # Real PAN should not be flagged as masked
        masked_aadhaar = [r for r in result if r["entity_type"] == "AADHAAR_MASKED"]
        assert len(masked_aadhaar) == 0


class TestBoostConfidence:
    def test_column_context_upgrades_medium_to_high(self) -> None:
        result = boost_confidence("MEDIUM", "AADHAAR", "AADHAAR", set())
        assert result == "HIGH"

    def test_inline_label_upgrades_medium_to_high(self) -> None:
        result = boost_confidence("MEDIUM", "PAN", None, {"PAN"})
        assert result == "HIGH"

    def test_no_context_no_change(self) -> None:
        result = boost_confidence("MEDIUM", "AADHAAR", None, set())
        assert result == "MEDIUM"

    def test_high_stays_high(self) -> None:
        result = boost_confidence("HIGH", "AADHAAR", "AADHAAR", set())
        assert result == "HIGH"

    def test_low_upgrades_to_medium(self) -> None:
        result = boost_confidence("LOW", "GSTIN", "GSTIN", set())
        assert result == "MEDIUM"

    def test_wrong_entity_no_boost(self) -> None:
        # Mobile in an "aadhaar" column should NOT be boosted
        result = boost_confidence("MEDIUM", "IN_MOBILE", "AADHAAR", set())
        assert result == "MEDIUM"

    def test_penalty_column_downgrades_to_low(self) -> None:
        # Serial number / Invoice columns should downgrade to LOW
        result = boost_confidence("HIGH", "AADHAAR", None, set(), column_name="sl_no")
        assert result == "LOW"

        result = boost_confidence("MEDIUM", "AADHAAR", None, set(), column_name="invoice_number")
        assert result == "LOW"

    def test_row_density_boost(self) -> None:
        # Neighbor context (pincode, address keywords) boosts confidence
        result = boost_confidence("MEDIUM", "AADHAAR", None, set(), has_row_context=True)
        assert result == "HIGH"

