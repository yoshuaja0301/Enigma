"""RAV — Risk Assessment Value (OSSTMM 3).

The RAV is OSSTMM's metric for *actual security*: instead of a subjective
severity score it measures the balance between what is exposed, what protects
it, and what is broken. It is deliberately **not** a CVSS-style opinion — it is
arithmetic over counted facts, which is exactly why it suits Enigma: every
number here comes from a verified observation, never from an AI's confidence.

Three inputs, per OSSTMM 3 (Chapter 3, "Operational Security Metrics"):

1. **OpSec (Porosity)** — the attack surface actually exposed:
   ``Visibility + Access + Trust``.
2. **Controls** — the ten operational controls in two classes:
   Class A (interactive): Authentication, Indemnification, Resilience,
   Subjugation, Continuity; Class B (process): Non-Repudiation,
   Confidentiality, Privacy, Integrity, Alarm.
3. **Limitations** — the flaws found, weighted by category:
   Vulnerability, Weakness, Concern, Exposure, Anomaly.

Each is reduced to a base-10 logarithmic magnitude (OSSTMM's ``sum → log``
form), combined into **Actual Security**, and reported as a percentage where
100 % is *perfect balance* — every porosity point fully covered by all ten
operational controls, with no limitations. Values above 100 % indicate controls
in excess of porosity; below 100 % indicates a security deficit.

Note how to read the score: a target with **zero flaws** still scores slightly
below 100 % if only some controls are evidenced. That is the point of the RAV —
it measures *balance*, not the absence of findings. Concretely,
``controls_sum`` equals ``opsec_sum`` exactly when ten controls are evidenced
per porosity point, which is the balance condition OSSTMM describes.

Enigma's mapping to these inputs is explicit and auditable:

* Only ``CONFIRMED`` findings become **Limitations** — an unproven hypothesis
  must never move a security metric.
* ``NOT_CONFIRMED`` findings contribute nothing (they were disproven).
* ``reported`` / ``INCONCLUSIVE`` findings are *counted separately* and excluded
  from the RAV, with the count surfaced so a reader knows the coverage the score
  rests on.
* Controls are credited only where verification actually observed the control
  working (e.g. a present CSP, an enforced HTTPS redirect).

References
----------
ISECOM, *OSSTMM 3: The Open Source Security Testing Methodology Manual*,
Chapter 3 (Operational Security Metrics) and Appendix A (RAV calculation).
"""

from __future__ import annotations

import math
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from ...findings.model import Verdict
from .controls import CLASS_A, CLASS_B, Control

# --------------------------------------------------------------------------- #
# Limitation categories and their OSSTMM weights.
#
# OSSTMM weights a limitation relative to the porosity it applies to. We use the
# standard ordering of severity from the manual: a Vulnerability (flaw granting
# access) outweighs a Weakness (a failed control), which outweighs a Concern
# (a control that logs/warns insufficiently), then Exposure (information
# disclosure) and Anomaly (unidentifiable behaviour).
# --------------------------------------------------------------------------- #
LIMITATION_WEIGHTS = {
    "vulnerability": 5.0,
    "weakness": 4.0,
    "concern": 3.0,
    "exposure": 2.0,
    "anomaly": 1.0,
}

# Which limitation class each verification check represents, and which
# operational control it evidences when the check comes back NOT_CONFIRMED
# (i.e. the protection was observed to be in place).
#
# check -> (limitation_class, control_evidenced_when_absent_of_flaw)
CHECK_LIMITATION_MAP: Dict[str, str] = {
    # Failed/missing controls -> Weakness
    "security_header": "weakness",
    "cookie_flags": "weakness",
    "tls_redirect": "weakness",
    "clickjacking": "weakness",
    "open_redirect": "weakness",
    # Access/trust granting flaws -> Vulnerability
    "cors": "vulnerability",
    "http_method": "vulnerability",
    # Information disclosure -> Exposure
    "directory_listing": "exposure",
    "server_version": "exposure",
    # Reflection is a trust/integrity concern until exploitation is proven
    "reflection": "concern",
}

CHECK_CONTROL_MAP: Dict[str, Control] = {
    "security_header": Control.INTEGRITY,
    "cookie_flags": Control.CONFIDENTIALITY,
    "tls_redirect": Control.CONFIDENTIALITY,
    "clickjacking": Control.INTEGRITY,
    "cors": Control.SUBJUGATION,
    "http_method": Control.AUTHENTICATION,
    "directory_listing": Control.PRIVACY,
    "server_version": Control.PRIVACY,
    "reflection": Control.INTEGRITY,
    "open_redirect": Control.SUBJUGATION,
}

_DEFAULT_LIMITATION = "anomaly"


def _log_sum(value: float) -> float:
    """OSSTMM's magnitude reduction: log10 of (1 + value), scaled by 10.

    Using ``1 + value`` keeps the function defined (and zero) at value 0, which
    is what OSSTMM's base-state requires.
    """

    return 10.0 * math.log10(1.0 + max(0.0, value))


@dataclass
class Porosity:
    """OpSec: the attack surface actually exposed."""

    visibility: int = 0  # targets/endpoints known to be reachable
    access: int = 0      # distinct interaction points (methods/params reachable)
    trust: int = 0       # places the target trusts external input/origins

    @property
    def total(self) -> int:
        return self.visibility + self.access + self.trust

    @property
    def opsec_sum(self) -> float:
        return _log_sum(self.total)

    def to_dict(self) -> dict:
        return {
            "visibility": self.visibility,
            "access": self.access,
            "trust": self.trust,
            "total": self.total,
            "opsec_sum": round(self.opsec_sum, 3),
        }


@dataclass
class Limitations:
    """Counted, verified flaws by OSSTMM category."""

    counts: Dict[str, int] = field(default_factory=dict)

    def add(self, category: str) -> None:
        category = category if category in LIMITATION_WEIGHTS else _DEFAULT_LIMITATION
        self.counts[category] = self.counts.get(category, 0) + 1

    @property
    def total(self) -> int:
        return sum(self.counts.values())

    def weighted(self, porosity_total: int) -> float:
        """OSSTMM weights limitations relative to porosity.

        A flaw on a large surface is proportionally less of the whole than the
        same flaw on a tiny surface, so the weight is scaled by porosity.
        """

        base = max(1, porosity_total)
        return sum(
            LIMITATION_WEIGHTS[cat] * count * (1.0 + 1.0 / base)
            for cat, count in self.counts.items()
        )

    def limitation_sum(self, porosity_total: int) -> float:
        return _log_sum(self.weighted(porosity_total))

    def to_dict(self, porosity_total: int) -> dict:
        return {
            "counts": dict(self.counts),
            "total": self.total,
            "weighted": round(self.weighted(porosity_total), 3),
            "limitation_sum": round(self.limitation_sum(porosity_total), 3),
        }


@dataclass
class Controls:
    """The ten OSSTMM operational controls, counted where evidenced."""

    counts: Dict[str, int] = field(default_factory=dict)

    def add(self, control: Control) -> None:
        self.counts[control.value] = self.counts.get(control.value, 0) + 1

    @property
    def total(self) -> int:
        return sum(self.counts.values())

    @property
    def class_a_total(self) -> int:
        return sum(c for k, c in self.counts.items() if any(k == a.value for a in CLASS_A))

    @property
    def class_b_total(self) -> int:
        return sum(c for k, c in self.counts.items() if any(k == b.value for b in CLASS_B))

    @property
    def missing(self) -> List[str]:
        present = set(self.counts)
        return sorted({c.value for c in Control} - present)

    @property
    def controls_sum(self) -> float:
        # OSSTMM divides the control count by 10 (the ten controls) before the
        # logarithmic reduction, so full coverage of one porosity point = 1.0.
        return _log_sum(self.total / 10.0)

    def to_dict(self) -> dict:
        return {
            "counts": dict(self.counts),
            "total": self.total,
            "class_a": self.class_a_total,
            "class_b": self.class_b_total,
            "missing": self.missing,
            "controls_sum": round(self.controls_sum, 3),
        }


@dataclass
class RavScore:
    """The computed RAV and everything needed to audit how it was derived."""

    porosity: Porosity
    controls: Controls
    limitations: Limitations
    actual_security: float
    true_protection: float
    true_coverage: float
    # Findings excluded from the RAV because they were never verified.
    excluded_unverified: int = 0
    basis: Dict[str, Any] = field(default_factory=dict)

    @property
    def security_deficit(self) -> float:
        """How far below perfect balance (100 %) the target sits."""

        return round(max(0.0, 100.0 - self.actual_security), 2)

    def grade(self) -> str:
        """A coarse, clearly-labelled band for reporting (not part of OSSTMM)."""

        a = self.actual_security
        if a >= 100.0:
            return "balanced"
        if a >= 90.0:
            return "adequate"
        if a >= 75.0:
            return "degraded"
        if a >= 50.0:
            return "poor"
        return "critical"

    def to_dict(self) -> dict:
        return {
            "methodology": "OSSTMM 3 RAV",
            "actual_security": round(self.actual_security, 2),
            "security_deficit": self.security_deficit,
            "grade": self.grade(),
            "true_protection": round(self.true_protection, 2),
            "true_coverage": round(self.true_coverage, 2),
            "porosity": self.porosity.to_dict(),
            "controls": self.controls.to_dict(),
            "limitations": self.limitations.to_dict(self.porosity.total),
            "excluded_unverified": self.excluded_unverified,
            "basis": self.basis,
        }


class RavCalculator:
    """Derives an OSSTMM RAV from Enigma verification results.

    Only *verified* observations feed the metric:

    * ``CONFIRMED``      → a Limitation (weighted by category)
    * ``NOT_CONFIRMED``  → evidence that the corresponding control is present
    * everything else    → excluded, but counted in ``excluded_unverified``
    """

    def compute(self, results: List[Any]) -> RavScore:
        porosity = Porosity()
        controls = Controls()
        limitations = Limitations()
        excluded = 0

        endpoints = set()
        trust_points = 0
        access_points = 0

        for result in results:
            finding = result.finding
            check = finding.check
            path = finding.target_path or "/"
            endpoints.add(path)

            verdict = result.verdict
            if verdict is Verdict.CONFIRMED:
                limitations.add(CHECK_LIMITATION_MAP.get(check or "", _DEFAULT_LIMITATION))
            elif verdict is Verdict.NOT_CONFIRMED:
                control = CHECK_CONTROL_MAP.get(check or "")
                if control is not None:
                    controls.add(control)
            else:
                excluded += 1

            # Porosity components observed during verification.
            if check in ("http_method", "cors"):
                access_points += 1
            if check in ("cors", "reflection"):
                trust_points += 1

        porosity.visibility = len(endpoints)
        porosity.access = access_points
        porosity.trust = trust_points

        opsec = porosity.opsec_sum
        ctrl = controls.controls_sum
        lims = limitations.limitation_sum(porosity.total)

        # True Protection: how much of the porosity is actually covered by
        # evidenced controls. True Coverage: the share of controls in place.
        true_protection = 100.0 * (ctrl / opsec) if opsec > 0 else 100.0
        true_coverage = 100.0 * (controls.total / 10.0) if controls.total else 0.0

        # Actual Security = perfect balance, reduced by unprotected porosity and
        # by verified limitations.
        actual_security = 100.0 + ctrl - opsec - lims
        actual_security = max(0.0, actual_security)

        return RavScore(
            porosity=porosity,
            controls=controls,
            limitations=limitations,
            actual_security=actual_security,
            true_protection=min(100.0, true_protection),
            true_coverage=min(100.0, true_coverage),
            excluded_unverified=excluded,
            basis={
                "opsec_sum": round(opsec, 3),
                "controls_sum": round(ctrl, 3),
                "limitation_sum": round(lims, 3),
                "formula": "actual_security = 100 + controls_sum - opsec_sum - limitation_sum",
                "verified_only": True,
                "endpoints_observed": sorted(endpoints),
            },
        )


def compute_rav(results: List[Any]) -> RavScore:
    """Convenience wrapper around :class:`RavCalculator`."""

    return RavCalculator().compute(results)
