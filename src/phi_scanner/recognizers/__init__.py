"""Recognizer registry — exports all identifier finders and auto-registers them.

Importing this package automatically registers every recognizer into
``RECOGNIZER_REGISTRY`` via the BaseRecognizer metaclass.

New recognizers are picked up automatically — no changes needed here.
"""
from .base import RECOGNIZER_REGISTRY, BaseRecognizer, RecognizerMatch

# Import all recognizers to trigger auto-registration
from .aadhaar import AadhaarMatch, Confidence, find_aadhaar, verhoeff_validate, verhoeff_check_digit
from .pan import PanMatch, find_pan
from .gstin import GstinMatch, find_gstin, validate_gstin, _gstin_check_digit
from .mobile import MobileMatch, find_mobile
from .voter_id import VoterIdMatch, find_voter_id
from .passport import PassportMatch, find_passport
from .bank_account import BankAccountRecognizer  # noqa: F401 — triggers registration

__all__ = [
    # Registry
    "RECOGNIZER_REGISTRY",
    "BaseRecognizer",
    "RecognizerMatch",
    # Legacy find_* API (preserved for backward compat)
    "find_aadhaar", "AadhaarMatch", "verhoeff_validate", "verhoeff_check_digit",
    "find_pan", "PanMatch",
    "find_gstin", "GstinMatch", "validate_gstin",
    "find_mobile", "MobileMatch",
    "find_voter_id", "VoterIdMatch",
    "find_passport", "PassportMatch",
    "Confidence",
]
