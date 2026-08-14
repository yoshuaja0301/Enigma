"""Assessment summary and research metrics.

Aggregates a batch of verification results into the numbers the Enigma research
questions care about: confirmation rate, false-positive-style rate (proposed but
NOT_CONFIRMED), inconclusive rate and reproducibility rate, plus a simple view
of how the AI's confidence related to the outcome.

It also breaks those numbers down **per finder** (`by_source`). Enigma accepts
findings from several sources — OpenClaw and the external instruments — and the
interesting question is not how many findings arrived but how many survived
verification, *per source*. See :class:`SourceStats` for the denominators.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from ..findings.model import Verdict
from ..methodologies.osstmm.modules import compute_module_coverage
from ..methodologies.osstmm.rav import compute_rav


@dataclass
class SourceStats:
    """Per-finder outcome counts.

    The rates deliberately divide by ``decided`` (CONFIRMED + NOT_CONFIRMED),
    not by ``total``. A `reported` or INCONCLUSIVE finding is one Enigma could
    not judge — counting it against the finder would report an opinion Enigma
    does not hold. ``undecided`` is published alongside so the reader can see
    how much of the finder's output was never adjudicated.
    """

    source: str = ""
    total: int = 0
    confirmed: int = 0
    not_confirmed: int = 0
    inconclusive: int = 0
    reported: int = 0
    blocked: int = 0
    avg_claimed_confidence: float = 0.0

    @property
    def decided(self) -> int:
        return self.confirmed + self.not_confirmed

    @property
    def undecided(self) -> int:
        return self.total - self.decided

    @property
    def confirmation_rate(self) -> float:
        """Share of this source's *decided* findings that Enigma confirmed."""
        return self.confirmed / self.decided if self.decided else 0.0

    @property
    def refutation_rate(self) -> float:
        """Share of this source's *decided* findings that Enigma refuted."""
        return self.not_confirmed / self.decided if self.decided else 0.0

    def to_dict(self) -> dict:
        return {
            "source": self.source,
            "total": self.total,
            "confirmed": self.confirmed,
            "not_confirmed": self.not_confirmed,
            "inconclusive": self.inconclusive,
            "reported": self.reported,
            "blocked": self.blocked,
            "decided": self.decided,
            "undecided": self.undecided,
            "confirmation_rate": round(self.confirmation_rate, 3),
            "refutation_rate": round(self.refutation_rate, 3),
            "rate_denominator": "decided",
            "avg_claimed_confidence": round(self.avg_claimed_confidence, 3),
        }


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
    osstmm_modules: Dict[str, Any] = field(default_factory=dict)
    # Outcome per finder (openclaw, nuclei, zap, nmap, whatweb, ...).
    by_source: Dict[str, SourceStats] = field(default_factory=dict)

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
            "osstmm_modules": self.osstmm_modules,
            "by_source": {name: stats.to_dict() for name, stats in self.by_source.items()},
        }


def summarize(results: List[Any], instruments: Optional[List[str]] = None) -> Summary:
    summary = Summary(total=len(results))
    conf_confirmed: List[float] = []
    conf_not_confirmed: List[float] = []
    coverage: Dict[str, int] = {}
    claimed: Dict[str, List[float]] = {}

    for result in results:
        source = getattr(result.finding, "source", None) or "unknown"
        stats = summary.by_source.setdefault(source, SourceStats(source=source))
        stats.total += 1
        claimed.setdefault(source, []).append(result.finding.confidence)

        if result.blocked:
            summary.blocked += 1
            stats.blocked += 1
        if result.reproducible:
            summary.reproducible += 1
        if result.status == "reported":
            summary.reported += 1
            stats.reported += 1

        if result.verdict is Verdict.CONFIRMED:
            summary.confirmed += 1
            stats.confirmed += 1
            conf_confirmed.append(result.finding.confidence)
        elif result.verdict is Verdict.NOT_CONFIRMED:
            summary.not_confirmed += 1
            stats.not_confirmed += 1
            conf_not_confirmed.append(result.finding.confidence)
        else:
            summary.inconclusive += 1
            stats.inconclusive += 1

        section = (result.methodology or {}).get("section")
        if section:
            coverage[section] = coverage.get(section, 0) + 1

    for source, values in claimed.items():
        summary.by_source[source].avg_claimed_confidence = _mean(values)

    summary.avg_ai_confidence_confirmed = _mean(conf_confirmed)
    summary.avg_ai_confidence_not_confirmed = _mean(conf_not_confirmed)
    summary.osstmm_coverage = coverage
    summary.rav = compute_rav(results).to_dict() if results else {}
    # Methodology coverage: declared instruments + the checks that actually ran.
    summary.osstmm_modules = compute_module_coverage(
        instruments=list(instruments or []) + ["enigma"],
        checks=[r.finding.check for r in results if getattr(r.finding, "check", None)],
    ).to_dict()
    return summary


def _mean(values: List[float]) -> float:
    return sum(values) / len(values) if values else 0.0
