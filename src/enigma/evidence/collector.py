"""Evidence collector and the Evidence model.

Collects the technical observations produced during verification into a single,
sanitized, reviewable artifact. Every exchange is passed through the sanitizer
before it is retained.
"""

from __future__ import annotations

import itertools
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from .sanitizer import EvidenceSanitizer

_counter = itertools.count(1)


@dataclass
class Evidence:
    evidence_id: str
    finding_id: str
    exchanges: List[Dict[str, Any]] = field(default_factory=list)
    observations: List[Dict[str, Any]] = field(default_factory=list)
    notes: List[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "evidence_id": self.evidence_id,
            "finding_id": self.finding_id,
            "exchanges": self.exchanges,
            "observations": self.observations,
            "notes": self.notes,
        }


class EvidenceCollector:
    """Builds sanitized :class:`Evidence` objects."""

    def __init__(self, sanitizer: Optional[EvidenceSanitizer] = None) -> None:
        self._sanitizer = sanitizer or EvidenceSanitizer()

    def collect(
        self,
        finding_id: str,
        exchanges: List[Dict[str, Any]],
        observations: List[Dict[str, Any]],
        notes: Optional[List[str]] = None,
    ) -> Evidence:
        clean_exchanges = [self._sanitizer.sanitize(ex) for ex in exchanges]
        clean_observations = [self._sanitizer.sanitize(ob) for ob in observations]
        clean_notes = [self._sanitizer.sanitize_text(n) for n in (notes or [])]
        return Evidence(
            evidence_id=self._next_id(),
            finding_id=finding_id,
            exchanges=clean_exchanges,
            observations=clean_observations,
            notes=clean_notes,
        )

    @staticmethod
    def _next_id() -> str:
        return f"EV-{next(_counter):05d}"
