"""Enigma service facade.

A single, transport-agnostic entry point that every integration surface (REST
API, webhook, MCP server, client SDK) wraps. It takes JSON-like dicts in and
returns JSON-like dicts out, so nothing above it needs to know about the
internal object model.

It also enforces an optional **server-side host allowlist**: even if a submitted
assessment claims a target is authorized, the service refuses to run against a
host the operator has not allow-listed at deploy time. This keeps an exposed
endpoint from being turned into a general-purpose scanner.
"""

from __future__ import annotations

from typing import Any, Dict, Iterable, List, Optional

from .agent.openclaw import StaticOpenClawAdapter
from .authorization.validator import AuthorizationValidator
from .controller import AssessmentController
from .core.configuration import load_assessment
from .reporting.json import build_report
from .verification.http import Transport


class EnigmaServiceError(Exception):
    """Base error for service-level rejections."""


class ServerScopeError(EnigmaServiceError):
    """Raised when a target host is outside the server-side allowlist."""


class EnigmaService:
    def __init__(
        self,
        transport: Optional[Transport] = None,
        evidence_dir: Optional[str] = None,
        allowed_hosts: Optional[Iterable[str]] = None,
    ) -> None:
        self._transport = transport
        self._evidence_dir = evidence_dir
        self._allowed_hosts = (
            {h.strip().lower() for h in allowed_hosts if h.strip()} if allowed_hosts else None
        )
        self._results: Dict[str, Dict[str, Any]] = {}

    # ------------------------------------------------------------------ #
    @property
    def allowlist_enabled(self) -> bool:
        return self._allowed_hosts is not None

    def _enforce_server_scope(self, assessment) -> None:
        if self._allowed_hosts is None:
            return
        host = assessment.target.host
        if host not in self._allowed_hosts:
            raise ServerScopeError(
                f"target host '{host}' is not in the server allowlist"
            )

    # ------------------------------------------------------------------ #
    def validate(self, assessment_data: Dict[str, Any]) -> Dict[str, Any]:
        """Run only the authorization/scope/policy gate. Sends no probes."""

        assessment = load_assessment(assessment_data)
        self._enforce_server_scope(assessment)
        validator = AuthorizationValidator(assessment)
        decision = validator.authorize(assessment.target.url, "GET")
        return {
            "assessment_id": assessment.assessment_id,
            "target": assessment.target.url,
            "allowed": decision.allowed,
            "stage": decision.stage.value,
            "reason": decision.reason,
        }

    def verify(
        self,
        assessment_data: Dict[str, Any],
        findings: Any,
    ) -> Dict[str, Any]:
        """Verify a batch of (OpenClaw) findings and return a full report."""

        assessment = load_assessment(assessment_data)
        self._enforce_server_scope(assessment)
        adapter = StaticOpenClawAdapter.from_data(findings if findings is not None else [])
        controller = AssessmentController(
            transport=self._transport, evidence_dir=self._evidence_dir
        )
        results = controller.run(assessment, adapter)
        report = build_report(results)
        self._results[assessment.assessment_id] = report
        return report

    def get_result(self, assessment_id: str) -> Optional[Dict[str, Any]]:
        """Return the most recent report for an assessment, if any."""

        return self._results.get(assessment_id)

    def list_results(self) -> List[str]:
        return list(self._results.keys())
