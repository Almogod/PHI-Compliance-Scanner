"""Recognizer registry — exports all v1 identifier finders."""
from .aadhaar import AadhaarMatch, Confidence, find_aadhaar, verhoeff_validate, verhoeff_check_digit
from .pan import PanMatch, find_pan
from .gstin import GstinMatch, find_gstin, validate_gstin, _gstin_check_digit
from .mobile import MobileMatch, find_mobile

__all__ = [
    "find_aadhaar", "AadhaarMatch", "verhoeff_validate", "verhoeff_check_digit",
    "find_pan", "PanMatch",
    "find_gstin", "GstinMatch", "validate_gstin",
    "find_mobile", "MobileMatch",
    "Confidence",
]
