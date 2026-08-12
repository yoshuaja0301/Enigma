"""Verification engine and safe probe procedures.

The engine takes a normalized finding and tries to *prove or disprove* it using
controlled, non-destructive probes. Everything a procedure sends passes through
the authorization-first gate (:class:`AuthorizationValidator`) via
:class:`ProbeContext`, so a procedure can never reach the network out of scope
or with a disallowed method.

The three built-in procedures are intentionally observational, not exploitative:

* ``security_header`` — GET the path and observe whether a security header is
  present or absent.
* ``reflection``      — send a benign random marker as a query value and observe
  whether it is reflected verbatim (a reflection *signal*, not an XSS payload).
* ``http_method``     — send OPTIONS and read the ``Allow`` header to observe
  whether a method is advertised.
"""

from __future__ import annotations

import secrets
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional
from urllib.parse import urlencode

from ..authorization.validator import AuthorizationResult, AuthorizationValidator, BlockStage
from ..core.assessment import Assessment
from ..evidence.collector import Evidence, EvidenceCollector
from ..evidence.store import EvidenceStore
from ..findings.model import Finding, Verdict
from .http import HttpResponse, Transport, UrllibTransport
from .profiles import VerificationProfile, verification_profile_for
from .reproducibility import ReproducibilityEngine

_BODY_EXCERPT = 512


class BlockedError(Exception):
    """Raised when a probe is refused by the authorization gate."""

    def __init__(self, result: AuthorizationResult) -> None:
        super().__init__(result.reason)
        self.result = result


@dataclass
class ProbeOutcome:
    condition_met: bool
    observation: Dict[str, Any]
    error: Optional[str] = None


@dataclass
class VerificationResult:
    assessment_id: str
    finding: Finding
    verdict: Verdict
    confidence: float
    reproducible: bool
    status: str  # completed | blocked | skipped | error
    procedure: Optional[str]
    observations: List[Dict[str, Any]] = field(default_factory=list)
    probes_run: int = 0
    evidence: Optional[Evidence] = None
    blocked: bool = False
    block_stage: BlockStage = BlockStage.NONE
    reason: str = ""
    methodology: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "assessment_id": self.assessment_id,
            "finding_id": self.finding.finding_id,
            "verdict": self.verdict.value,
            "confidence": round(self.confidence, 2),
            "reproducible": self.reproducible,
            "target": {
                "host": self.finding.target_host,
                "path": self.finding.target_path,
            },
            "finding": {
                "type": self.finding.type,
                "category": self.finding.category,
                "check": self.finding.check,
                "title": self.finding.title,
                "description": self.finding.description,
                "ai_confidence": round(self.finding.confidence, 2),
            },
            "verification": {
                "status": self.status,
                "procedure": self.procedure,
                "probes_run": self.probes_run,
                "observations": self.observations,
                "reason": self.reason,
            },
            "evidence": {"evidence_id": self.evidence.evidence_id} if self.evidence else None,
            "methodology": self.methodology or {"name": "OSSTMM"},
        }


class ProbeContext:
    """Per-finding, authorization-gated request helper handed to procedures."""

    def __init__(
        self,
        assessment: Assessment,
        validator: AuthorizationValidator,
        transport: Transport,
        profile: VerificationProfile,
        finding: Finding,
    ) -> None:
        self._base_url = assessment.target.base_url()
        self._validator = validator
        self._transport = transport
        self._profile = profile
        self._finding = finding
        self.exchanges: List[Dict[str, Any]] = []

    def build_url(self, path: Optional[str] = None, query: Optional[Dict[str, str]] = None) -> str:
        path = path or self._finding.target_path or "/"
        if not path.startswith("/"):
            path = "/" + path
        url = self._base_url + path
        if query:
            url = f"{url}?{urlencode(query)}"
        return url

    def send(
        self,
        method: str,
        path: Optional[str] = None,
        query: Optional[Dict[str, str]] = None,
        headers: Optional[Dict[str, str]] = None,
    ) -> HttpResponse:
        url = self.build_url(path, query)
        decision = self._validator.authorize(url, method)
        if not decision.allowed:
            raise BlockedError(decision)

        policy = self._profile.policy
        response = self._transport.request(
            method,
            url,
            headers=headers,
            timeout=10.0,
            max_body_bytes=policy.max_body_bytes,
        )
        self.exchanges.append(
            {
                "request": {"method": method.upper(), "url": url, "headers": dict(headers or {})},
                "response": {
                    "status": response.status,
                    "headers": dict(response.headers),
                    "body_excerpt": response.body[:_BODY_EXCERPT],
                    "error": response.error,
                },
            }
        )
        return response


# --------------------------------------------------------------------------- #
# Procedures
# --------------------------------------------------------------------------- #
class SecurityHeaderProcedure:
    key = "security_header"

    def applies_to(self, finding: Finding) -> bool:
        return bool(finding.parameters.get("header"))

    def probe(self, ctx: ProbeContext, finding: Finding) -> ProbeOutcome:
        header = str(finding.parameters["header"])
        resp = ctx.send("GET")
        if resp.status == 0:
            return ProbeOutcome(False, {"check": "security_header", "header": header}, error=resp.error or "request failed")
        present = resp.has_header(header)
        # Hypothesis being tested: the security header is MISSING (a weakness).
        condition_met = not present
        return ProbeOutcome(
            condition_met=condition_met,
            observation={
                "check": "security_header",
                "header": header,
                "present": present,
                "status": resp.status,
            },
        )


class ReflectionProcedure:
    key = "reflection"

    def applies_to(self, finding: Finding) -> bool:  # noqa: ARG002 - always applicable
        return True

    def probe(self, ctx: ProbeContext, finding: Finding) -> ProbeOutcome:
        param = str(finding.parameters.get("param", "q"))
        marker = "enigma" + secrets.token_hex(6)  # benign alphanumeric marker
        resp = ctx.send("GET", query={param: marker})
        if resp.status == 0:
            return ProbeOutcome(False, {"check": "reflection", "param": param}, error=resp.error or "request failed")
        reflected = marker in resp.body
        return ProbeOutcome(
            condition_met=reflected,
            observation={
                "check": "reflection",
                "param": param,
                "marker_reflected": reflected,
                "status": resp.status,
            },
        )


class HttpMethodProcedure:
    key = "http_method"

    def applies_to(self, finding: Finding) -> bool:
        return bool(finding.parameters.get("method"))

    def probe(self, ctx: ProbeContext, finding: Finding) -> ProbeOutcome:
        method = str(finding.parameters["method"]).upper()
        resp = ctx.send("OPTIONS")
        if resp.status == 0:
            return ProbeOutcome(False, {"check": "http_method", "method": method}, error=resp.error or "request failed")
        allow = resp.header("Allow") or ""
        advertised = [m.strip().upper() for m in allow.split(",") if m.strip()]
        if not allow:
            return ProbeOutcome(
                False,
                {"check": "http_method", "method": method, "allow_header": None, "status": resp.status},
                error="no Allow header advertised",
            )
        condition_met = method in advertised
        return ProbeOutcome(
            condition_met=condition_met,
            observation={
                "check": "http_method",
                "method": method,
                "advertised": advertised,
                "status": resp.status,
            },
        )


_DEFAULT_PROCEDURES = {
    SecurityHeaderProcedure.key: SecurityHeaderProcedure(),
    ReflectionProcedure.key: ReflectionProcedure(),
    HttpMethodProcedure.key: HttpMethodProcedure(),
}


class VerificationEngine:
    """Runs verification for a single finding and returns a verdict + evidence."""

    def __init__(
        self,
        transport: Optional[Transport] = None,
        procedures: Optional[Dict[str, Any]] = None,
        collector: Optional[EvidenceCollector] = None,
        store: Optional[EvidenceStore] = None,
    ) -> None:
        self._transport = transport or UrllibTransport()
        self._procedures = dict(procedures or _DEFAULT_PROCEDURES)
        self._collector = collector or EvidenceCollector()
        self._store = store or EvidenceStore()
        self._reproducibility = ReproducibilityEngine()

    def verify(self, assessment: Assessment, finding: Finding) -> VerificationResult:
        profile = verification_profile_for(assessment.profile)
        validator = AuthorizationValidator(assessment, profile.policy)

        # Pre-flight authorization/scope check so a blocked assessment sends
        # nothing at all.
        preflight = validator.authorize(_finding_url(assessment, finding), "GET")
        if not preflight.allowed and preflight.stage in (BlockStage.AUTHORIZATION, BlockStage.SCOPE):
            return self._blocked(assessment, finding, preflight)

        procedure = self._procedures.get(finding.check) if finding.check else None
        if procedure is None:
            # OpenClaw is free to report any finding type. One without a safe
            # automated check is NOT dropped — it is kept for a human to verify.
            return self._skipped(
                assessment,
                finding,
                reason="no automated verification for this finding type; recorded for manual review",
                status="needs_manual_review",
            )
        if not procedure.applies_to(finding):
            return self._skipped(
                assessment,
                finding,
                reason=f"procedure '{finding.check}' requires additional parameters",
                status="needs_manual_review",
            )

        ctx = ProbeContext(assessment, validator, self._transport, profile, finding)
        repeat = max(1, min(profile.repeat_count, profile.policy.max_probes_per_finding))
        outcomes: List[ProbeOutcome] = []
        try:
            for index in range(repeat):
                outcomes.append(procedure.probe(ctx, finding))
                if profile.policy.request_delay_seconds and index + 1 < repeat:
                    time.sleep(profile.policy.request_delay_seconds)
        except BlockedError as blocked:
            return self._blocked(assessment, finding, blocked.result, exchanges=ctx.exchanges)

        return self._finalize(assessment, finding, procedure.key, outcomes, ctx)

    # ------------------------------------------------------------------ #
    def _finalize(
        self,
        assessment: Assessment,
        finding: Finding,
        procedure_key: str,
        outcomes: List[ProbeOutcome],
        ctx: ProbeContext,
    ) -> VerificationResult:
        observations = [
            {**o.observation, **({"error": o.error} if o.error else {})} for o in outcomes
        ]
        successful = [o for o in outcomes if o.error is None]

        evidence = self._maybe_collect(finding, ctx.exchanges, observations)

        if not successful:
            reason = successful_error_reason(outcomes)
            return VerificationResult(
                assessment_id=assessment.assessment_id,
                finding=finding,
                verdict=Verdict.INCONCLUSIVE,
                confidence=0.3,
                reproducible=False,
                status="error",
                procedure=procedure_key,
                observations=observations,
                probes_run=len(outcomes),
                evidence=evidence,
                reason=reason,
            )

        condition_results = [o.condition_met for o in successful]
        repro = self._reproducibility.assess(condition_results)

        if repro.consistent and all(condition_results):
            verdict = Verdict.CONFIRMED
            confidence = 0.5 + 0.45 * repro.ratio
            reason = "condition consistently observed across probes"
        elif repro.consistent and not any(condition_results):
            verdict = Verdict.NOT_CONFIRMED
            confidence = 0.5 + 0.45 * (1 - repro.ratio)
            reason = "expected condition was not reproduced"
        else:
            verdict = Verdict.INCONCLUSIVE
            confidence = 0.3
            reason = "inconsistent results across probes"

        return VerificationResult(
            assessment_id=assessment.assessment_id,
            finding=finding,
            verdict=verdict,
            confidence=confidence,
            reproducible=repro.reproducible,
            status="completed",
            procedure=procedure_key,
            observations=observations,
            probes_run=len(outcomes),
            evidence=evidence,
            reason=reason,
        )

    def _maybe_collect(
        self,
        finding: Finding,
        exchanges: List[Dict[str, Any]],
        observations: List[Dict[str, Any]],
    ) -> Optional[Evidence]:
        if not exchanges:
            return None
        evidence = self._collector.collect(finding.finding_id, exchanges, observations)
        self._store.save(evidence)
        return evidence

    def _blocked(
        self,
        assessment: Assessment,
        finding: Finding,
        decision: AuthorizationResult,
        exchanges: Optional[List[Dict[str, Any]]] = None,
    ) -> VerificationResult:
        evidence = None
        if exchanges:
            evidence = self._collector.collect(finding.finding_id, exchanges, [])
            self._store.save(evidence)
        return VerificationResult(
            assessment_id=assessment.assessment_id,
            finding=finding,
            verdict=Verdict.INCONCLUSIVE,
            confidence=0.0,
            reproducible=False,
            status="blocked",
            procedure=None,
            observations=[],
            probes_run=0,
            evidence=evidence,
            blocked=True,
            block_stage=decision.stage,
            reason=f"ASSESSMENT BLOCKED ({decision.stage.value}): {decision.reason}",
        )

    def _skipped(
        self,
        assessment: Assessment,
        finding: Finding,
        reason: str,
        status: str = "skipped",
    ) -> VerificationResult:
        return VerificationResult(
            assessment_id=assessment.assessment_id,
            finding=finding,
            verdict=Verdict.INCONCLUSIVE,
            confidence=0.3,
            reproducible=False,
            status=status,
            procedure=finding.check,
            observations=[],
            probes_run=0,
            reason=reason,
        )

    @property
    def store(self) -> EvidenceStore:
        return self._store


def successful_error_reason(outcomes: List[ProbeOutcome]) -> str:
    errors = [o.error for o in outcomes if o.error]
    if errors:
        return f"all probes failed: {errors[0]}"
    return "no successful probes"


def _finding_url(assessment: Assessment, finding: Finding) -> str:
    path = finding.target_path or "/"
    if not path.startswith("/"):
        path = "/" + path
    return assessment.target.base_url() + path
