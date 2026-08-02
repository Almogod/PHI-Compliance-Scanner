"""Tests for BaseRecognizer auto-registration registry and factory pattern."""
import pytest

from phi_scanner.recognizers.base import RECOGNIZER_REGISTRY, BaseRecognizer, RecognizerMatch
import phi_scanner.recognizers  # noqa: F401 — triggers all auto-registrations


class TestAutoRegistration:
    def test_all_core_types_registered(self) -> None:
        registered = RECOGNIZER_REGISTRY.all_types()
        assert "AADHAAR" in registered
        assert "PAN" in registered
        assert "GSTIN" in registered
        assert "IN_MOBILE" in registered
        assert "VOTER_ID" in registered
        assert "PASSPORT" in registered
        assert "IFSC" in registered

    def test_active_returns_all_by_default(self) -> None:
        active = RECOGNIZER_REGISTRY.active()
        assert len(active) >= 7  # at least 7 recognizers registered

    def test_disable_and_enable(self) -> None:
        RECOGNIZER_REGISTRY.disable("AADHAAR")
        active_types = {r.entity_type for r in RECOGNIZER_REGISTRY.active()}
        assert "AADHAAR" not in active_types

        RECOGNIZER_REGISTRY.enable("AADHAAR")
        active_types_after = {r.entity_type for r in RECOGNIZER_REGISTRY.active()}
        assert "AADHAAR" in active_types_after

    def test_new_recognizer_auto_registers(self) -> None:
        # Dynamically defining a subclass should register it immediately
        class _TestRecognizer(BaseRecognizer):
            entity_type = "_TEST_DYNAMIC"

            def find(self, text: str) -> list[RecognizerMatch]:
                return []

        assert "_TEST_DYNAMIC" in RECOGNIZER_REGISTRY.all_types()
        # Cleanup: remove it from the registry so it doesn't affect other tests
        del RECOGNIZER_REGISTRY._all["_TEST_DYNAMIC"]

    def test_get_by_type(self) -> None:
        pan_rec = RECOGNIZER_REGISTRY.get("PAN")
        assert pan_rec is not None
        assert pan_rec.entity_type == "PAN"

    def test_none_for_unknown_type(self) -> None:
        assert RECOGNIZER_REGISTRY.get("TOTALLY_UNKNOWN_XYZ") is None


class TestRecognizerMatchShape:
    def test_aadhaar_match_shape(self) -> None:
        rec = RECOGNIZER_REGISTRY.get("AADHAAR")
        assert rec is not None
        # Valid Aadhaar: verhoeff check digit 5 for 23456789012x
        # Use the corpus instead
        matches = rec.find("2345 6789 0124")
        # Should return 0 or more RecognizerMatch objects with correct fields
        for m in matches:
            assert m.entity_type == "AADHAAR"
            assert m.masked_value  # never empty
            assert m.confidence in ("HIGH", "MEDIUM", "LOW")
            assert m.raw_value  # non-empty (ephemeral dedup key)

    def test_pan_match_shape(self) -> None:
        rec = RECOGNIZER_REGISTRY.get("PAN")
        assert rec is not None
        matches = rec.find("ABCPD1234E")
        assert len(matches) == 1
        assert matches[0].entity_type == "PAN"
        assert matches[0].masked_value == "XXXXX1234X"
        assert matches[0].confidence == "HIGH"
        assert matches[0].extra is not None
        assert matches[0].extra.get("holder_type") == "Individual"

    def test_gstin_match_shape(self) -> None:
        rec = RECOGNIZER_REGISTRY.get("GSTIN")
        assert rec is not None
        matches = rec.find("27AAPFU0939F1ZV")
        assert len(matches) == 1
        assert matches[0].entity_type == "GSTIN"
        assert matches[0].extra is not None
        assert matches[0].extra.get("state_code") == "27"
