"""Reproducibility assessment.

Given the boolean outcome of repeating the same probe N times, decide whether
the finding's condition reproduces *consistently*. Consistency (all-true or
all-false) is what lets Enigma issue a confident verdict; a mixed result is a
signal to stay INCONCLUSIVE.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import List


@dataclass(frozen=True)
class ReproducibilityReport:
    reproducible: bool
    ratio: float  # fraction of runs where the condition was met
    runs: int
    consistent: bool  # all runs agreed (all true OR all false)


class ReproducibilityEngine:
    def assess(self, condition_results: List[bool]) -> ReproducibilityReport:
        runs = len(condition_results)
        if runs == 0:
            return ReproducibilityReport(reproducible=False, ratio=0.0, runs=0, consistent=False)

        met = sum(1 for c in condition_results if c)
        ratio = met / runs
        consistent = met == 0 or met == runs
        # "reproducible" means the observed behavior repeated consistently
        # across every run — regardless of whether that behavior confirmed or
        # refuted the finding.
        reproducible = consistent and runs >= 1
        return ReproducibilityReport(
            reproducible=reproducible,
            ratio=ratio,
            runs=runs,
            consistent=consistent,
        )
