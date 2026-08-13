"""Assessment controller.

Ties the pieces together into the pipeline described in the design doc:

    OpenClaw findings
        -> normalize
        -> authorization / scope / policy gate (inside the engine)
        -> verification (+ reproducibility)
        -> evidence (sanitized)
        -> OSSTMM mapping
        -> results / report

The controller is the single entry point most callers (CLI, tests, notebooks)
should use.
"""

from __future__ import annotations

from typing import List, Optional

from .agent.openclaw import OpenClawAdapter
from .core.assessment import Assessment
from .evidence.store import EvidenceStore
from .findings.normalizer import FindingNormalizer
from .methodologies.osstmm import OsstmmMapper
from .reporting.summary import Summary, summarize
from .verification.engine import VerificationEngine, VerificationResult
from .verification.http import Transport


class AssessmentController:
    def __init__(
        self,
        transport: Optional[Transport] = None,
        evidence_dir: Optional[str] = None,
    ) -> None:
        self._normalizer = FindingNormalizer()
        self._store = EvidenceStore(evidence_dir)
        self._engine = VerificationEngine(transport=transport, store=self._store)
        self._mapper = OsstmmMapper()

    def run(self, assessment: Assessment, adapter: OpenClawAdapter) -> List[VerificationResult]:
        raw_findings = adapter.get_findings(assessment)
        findings = self._normalizer.normalize_many(raw_findings)

        results: List[VerificationResult] = []
        for finding in findings:
            # Default the finding host to the assessment target when the agent
            # did not specify one.
            if not finding.target_host:
                finding.target_host = assessment.target.host
            result = self._engine.verify(assessment, finding)
            result.methodology = self._mapper.map(finding, result.verdict)
            results.append(result)
        return results

    def summarize(
        self, results: List[VerificationResult], assessment: Optional[Assessment] = None
    ) -> Summary:
        instruments = list(assessment.instruments) if assessment else None
        return summarize(results, instruments=instruments)

    @property
    def evidence_store(self) -> EvidenceStore:
        return self._store
