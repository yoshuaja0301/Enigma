"""Enigma — evidence-based verification for authorized web vulnerability assessment.

Enigma is a *proof layer* for AI-assisted web security assessment. An AI agent
(OpenClaw) proposes potential findings; Enigma validates authorization and
scope, verifies each finding with controlled, non-destructive probes, collects
sanitized evidence, checks reproducibility and maps results to OSSTMM — issuing
a CONFIRMED / NOT_CONFIRMED / INCONCLUSIVE verdict.
"""

from __future__ import annotations

from .agent.openclaw import OpenClawAdapter, StaticOpenClawAdapter
from .controller import AssessmentController
from .core.assessment import (
    Assessment,
    AssessmentProfile,
    Authorization,
    AuthorizationStatus,
    Scope,
)
from .core.configuration import load_assessment
from .core.target import Target
from .findings.model import Finding, Verdict
from .findings.normalizer import FindingNormalizer
from .methodologies.osstmm import OsstmmMapper
from .verification.engine import VerificationEngine, VerificationResult

__version__ = "0.1.0"

__all__ = [
    "__version__",
    "Assessment",
    "AssessmentProfile",
    "Authorization",
    "AuthorizationStatus",
    "Scope",
    "Target",
    "load_assessment",
    "Finding",
    "Verdict",
    "FindingNormalizer",
    "OpenClawAdapter",
    "StaticOpenClawAdapter",
    "VerificationEngine",
    "VerificationResult",
    "OsstmmMapper",
    "AssessmentController",
]
