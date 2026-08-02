"""Base class and auto-registration registry for all PII recognizers.

Design
------
Every recognizer *class* that subclasses ``BaseRecognizer`` is automatically
added to the global ``RECOGNIZER_REGISTRY`` at class-definition time via the
``RecognizerMeta`` metaclass.

This means:
  - Adding a new recognizer requires creating a subclass — no engine changes needed.
  - Disabling a recognizer is one line: ``RECOGNIZER_REGISTRY.disable("BANK_ACCOUNT")``.
  - The CLI can expose ``--disable <entity_type>`` without touching engine logic.

Usage
-----
From the engine or pipeline:

    from phi_scanner.recognizers.base import RECOGNIZER_REGISTRY
    for recognizer in RECOGNIZER_REGISTRY.active():
        for match in recognizer.find(chunk):
            ...  # match is a RecognizerMatch

Every ``BaseRecognizer`` subclass must implement:
    - ``entity_type: ClassVar[str]``   — e.g. "AADHAAR", "PAN"
    - ``find(text: str) -> list[RecognizerMatch]``
"""
from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import ClassVar


# ---------------------------------------------------------------------------
# Canonical match output — all recognizers emit this shape
# ---------------------------------------------------------------------------

@dataclass(frozen=True, slots=True)
class RecognizerMatch:
    """Canonical output emitted by every recognizer's ``find()`` method.

    Attributes
    ----------
    entity_type:
        Uppercase string identifying the PII category (e.g. "AADHAAR", "PAN").
    raw_value:
        The original, un-masked extracted string. **Never stored in reports.**
        Used only for deduplication keys inside the engine during a single scan
        session and is discarded immediately thereafter.
    masked_value:
        Permanently sanitized form safe to include in audit logs.
    confidence:
        ``"HIGH"`` | ``"MEDIUM"`` | ``"LOW"`` — pre-context base confidence.
    extra:
        Optional structured metadata dict (e.g. holder_type for PAN, state_code
        for GSTIN). Included in reports for auditor context.
    """
    entity_type: str
    raw_value: str        # ← ephemeral; never written to report
    masked_value: str
    confidence: str       # "HIGH" | "MEDIUM" | "LOW"
    extra: dict[str, str] | None = None


# ---------------------------------------------------------------------------
# Metaclass — auto-registration on class creation
# ---------------------------------------------------------------------------

class _RecognizerRegistry:
    """Thread-safe central registry of all active recognizers."""

    def __init__(self) -> None:
        self._all: dict[str, "BaseRecognizer"] = {}
        self._disabled: set[str] = set()

    def _register(self, cls: "type[BaseRecognizer]") -> None:
        """Called by RecognizerMeta immediately after class body execution."""
        instance = cls()
        self._all[instance.entity_type] = instance

    def active(self) -> list["BaseRecognizer"]:
        """Return all non-disabled recognizer instances in deterministic order."""
        return [
            r for et, r in sorted(self._all.items())
            if et not in self._disabled
        ]

    def disable(self, entity_type: str) -> None:
        """Suppress a recognizer without removing it from the registry."""
        self._disabled.add(entity_type.upper())

    def enable(self, entity_type: str) -> None:
        """Re-enable a previously disabled recognizer."""
        self._disabled.discard(entity_type.upper())

    def get(self, entity_type: str) -> "BaseRecognizer | None":
        return self._all.get(entity_type.upper())

    def all_types(self) -> list[str]:
        return sorted(self._all.keys())


RECOGNIZER_REGISTRY: _RecognizerRegistry = _RecognizerRegistry()


class RecognizerMeta(type(ABC)):
    """Metaclass that auto-registers any concrete BaseRecognizer subclass."""

    def __new__(
        mcs,
        name: str,
        bases: tuple[type, ...],
        namespace: dict,
        **kwargs: object,
    ) -> "RecognizerMeta":
        cls = super().__new__(mcs, name, bases, namespace, **kwargs)
        # Only register concrete classes (those that have entity_type set and
        # are not the abstract base itself).
        if bases and hasattr(cls, "entity_type") and cls.entity_type:  # type: ignore[attr-defined]
            RECOGNIZER_REGISTRY._register(cls)  # type: ignore[arg-type]
        return cls


# ---------------------------------------------------------------------------
# Abstract base class
# ---------------------------------------------------------------------------

class BaseRecognizer(ABC, metaclass=RecognizerMeta):
    """Abstract base for all PII recognizers.

    Subclass this, set ``entity_type``, implement ``find()``, and the
    recognizer is automatically registered in ``RECOGNIZER_REGISTRY``.

    Example
    -------
    class MyRecognizer(BaseRecognizer):
        entity_type = "MY_PII"

        def find(self, text: str) -> list[RecognizerMatch]:
            ...
    """

    entity_type: ClassVar[str] = ""  # Concrete subclasses MUST override this

    @abstractmethod
    def find(self, text: str) -> list[RecognizerMatch]:
        """Return all matches found in *text*, pre-masked and confidence-rated.

        Implementations:
          - Must NOT raise exceptions on empty or malformed input.
          - Must NOT perform I/O (network, disk) of any kind.
          - Must return an empty list if no matches are found.
          - raw_value on each match should be the full, unmasked original string
            (used only for in-memory deduplication; never logged or saved).
        """
        ...
