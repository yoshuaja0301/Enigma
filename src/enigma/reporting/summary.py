"""Assessment summary and research metrics.

Aggregates a batch of verification results into the numbers the Enigma research
questions care about: confirmation rate, false-positive-style rate (proposed but
NOT_CONFIRMED), inconclusive rate and reproducibility rate, plus a simple view
of how the AI's confidence related to the outcome.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List

from ..findings.model import Verdict
from ..methodologies.osstmm.rav import compute_rav


@dataclass
class Summary:
    total: int = 0
    confirmed: int = 0
    not_confirmed: int = 0
    inconclusive: int = 0
    blocked: int = 0
    reproducible: int = 0
    reported: int = 0  # reported by OpenClaw, no automatic check — recorded for review
    avg_ai_confidence_confirmed: float = 0.0
    avg_ai_confidence_not_confirmed: float = 0.0
    osstmm_coverage: Dict[str, int] = field(default_factory=dict)
    # OSSTMM RAV, computed from verified observations only.
    rav: Dict[str, Any] = field(default_factory=dict)

    @property
    def confirmation_rate(self) -> float:
        return self.confirmed / self.total if self.total else 0.0

    @property
    def false_positive_rate(self) -> float:
        # Findings proposed by the agent that verification could not confirm.
        return self.not_confirmed / self.total if self.total else 0.0

    @property
    def inconclusive_rate(self) -> float:
        return self.inconclusive / self.total if self.total else 0.0

    def to_dict(self) -> dict:
        return {
            "total": self.total,
            "confirmed": self.confirmed,
            "not_confirmed": self.not_confirmed,
            "inconclusive": self.inconclusive,
            "blocked": self.blocked,
            "reproducible": self.reproducible,
            "reported": self.reported,
            "confirmation_rate": round(self.confirmation_rate, 3),
            "false_positive_rate": round(self.false_positive_rate, 3),
            "inconclusive_rate": round(self.inconclusive_rate, 3),
            "avg_ai_confidence_confirmed": round(self.avg_ai_confidence_confirmed, 3),
            "avg_ai_confidence_not_confirmed": round(self.avg_ai_confidence_not_confirmed, 3),
            "osstmm_coverage": self.osstmm_coverage,
            "rav": self.rav,
        }


def summarize(results: List[Any]) -> Summary:
    summary = Summary(total=len(results))
    conf_confirmed: List[float] = []
    conf_not_confirmed: List[float] = []
    coverage: Dict[str, int] = {}

    for result in results:
        if result.blocked:
            summary.blocked += 1
        if result.reproducible:
            summary.reproducible += 1
        if result.status == "reported":
            summary.reported += 1

        if result.verdict is Verdict.CONFIRMED:
            summary.confirmed += 1
            conf_confirmed.append(result.finding.confidence)
        elif result.verdict is Verdict.NOT_CONFIRMED:
            summary.not_confirmed += 1
            conf_not_confirmed.append(result.finding.confidence)
        else:
            summary.inconclusive += 1

        section = (result.methodology or {}).get("section")
        if section:
            coverage[section] = coverage.get(section, 0) + 1

    summary.avg_ai_confidence_confirmed = _mean(conf_confirmed)
    summary.avg_ai_confidence_not_confirmed = _mean(conf_not_confirmed)
    summary.osstmm_coverage = coverage
    summary.rav = compute_rav(results).to_dict() if results else {}
    return summary


def _mean(values: List[float]) -> float:
    return sum(values) / len(values) if values else 0.0
