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

import re
import secrets
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional
from urllib.parse import urlencode, urlsplit, urlunsplit

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
        url: Optional[str] = None,
    ) -> HttpResponse:
        # An explicit `url` (e.g. the http:// variant for a TLS-redirect probe)
        # still passes through the authorization gate before anything is sent.
        url = url or self.build_url(path, query)
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


class CookieFlagsProcedure:
    """Observe whether a Set-Cookie is missing a security flag.

    Non-destructive: a single GET, then inspection of Set-Cookie headers.
    Hypothesis (weakness) = the required flag is ABSENT on the relevant cookie.
    """

    key = "cookie_flags"
    _CANONICAL = {"secure": "Secure", "httponly": "HttpOnly", "samesite": "SameSite"}

    def applies_to(self, finding: Finding) -> bool:
        return bool(finding.parameters.get("flag"))

    def probe(self, ctx: ProbeContext, finding: Finding) -> ProbeOutcome:
        flag_raw = str(finding.parameters["flag"])
        flag = self._CANONICAL.get(flag_raw.strip().lower(), flag_raw)
        cookie_name = finding.parameters.get("cookie")

        resp = ctx.send("GET")
        if resp.status == 0:
            return ProbeOutcome(False, {"check": "cookie_flags", "flag": flag}, error=resp.error or "request failed")

        cookies = resp.set_cookies()
        if cookie_name:
            cookies = [c for c in cookies if c.split("=", 1)[0].strip().lower() == str(cookie_name).lower()]
        if not cookies:
            return ProbeOutcome(
                False,
                {"check": "cookie_flags", "flag": flag, "cookies_seen": 0},
                error="no matching Set-Cookie observed",
            )

        missing = [c.split("=", 1)[0].strip() for c in cookies if flag.lower() not in c.lower()]
        condition_met = len(missing) > 0  # at least one cookie lacks the flag
        return ProbeOutcome(
            condition_met=condition_met,
            observation={
                "check": "cookie_flags",
                "flag": flag,
                "cookies_seen": len(cookies),
                "cookies_missing_flag": missing,
                "status": resp.status,
            },
        )


class CorsProcedure:
    """Observe whether the server reflects an arbitrary Origin (permissive CORS).

    Non-destructive: a GET carrying a benign `Origin` header. Hypothesis
    (weakness) = the response reflects that origin (or `*`) in
    Access-Control-Allow-Origin — worse still with Allow-Credentials: true.
    """

    key = "cors"
    _PROBE_ORIGIN = "https://enigma-cors-probe.example"

    def applies_to(self, finding: Finding) -> bool:  # noqa: ARG002 - always applicable
        return True

    def probe(self, ctx: ProbeContext, finding: Finding) -> ProbeOutcome:
        origin = str(finding.parameters.get("origin", self._PROBE_ORIGIN))
        resp = ctx.send("GET", headers={"Origin": origin})
        if resp.status == 0:
            return ProbeOutcome(False, {"check": "cors", "origin": origin}, error=resp.error or "request failed")

        acao = resp.header("Access-Control-Allow-Origin")
        acac = (resp.header("Access-Control-Allow-Credentials") or "").strip().lower() == "true"
        reflected = acao == origin
        wildcard = acao == "*"
        condition_met = reflected or wildcard
        return ProbeOutcome(
            condition_met=condition_met,
            observation={
                "check": "cors",
                "origin_sent": origin,
                "access_control_allow_origin": acao,
                "allow_credentials": acac,
                "reflects_origin": reflected,
                "wildcard": wildcard,
                # reflected origin + credentials is the dangerous combination
                "credentialed_reflection": reflected and acac,
                "status": resp.status,
            },
        )


class TlsRedirectProcedure:
    """Observe whether plain HTTP is upgraded to HTTPS (and note HSTS).

    Non-destructive: a single GET to the http:// variant (redirects are observed,
    never followed). Hypothesis (weakness) = HTTP is served without redirecting
    to HTTPS.
    """

    key = "tls_redirect"

    def applies_to(self, finding: Finding) -> bool:  # noqa: ARG002 - always applicable
        return True

    def probe(self, ctx: ProbeContext, finding: Finding) -> ProbeOutcome:
        parsed = urlsplit(ctx.build_url(finding.target_path))
        http_url = urlunsplit(("http", parsed.hostname + (f":{parsed.port}" if parsed.port else ""),
                               parsed.path or "/", "", ""))
        resp = ctx.send("GET", url=http_url)
        if resp.status == 0:
            return ProbeOutcome(False, {"check": "tls_redirect", "http_url": http_url}, error=resp.error or "request failed")

        location = resp.header("Location") or ""
        redirects_to_https = 300 <= resp.status < 400 and location.lower().startswith("https://")
        hsts_present = resp.has_header("Strict-Transport-Security")
        # Weakness: HTTP is not upgraded to HTTPS.
        condition_met = not redirects_to_https
        return ProbeOutcome(
            condition_met=condition_met,
            observation={
                "check": "tls_redirect",
                "http_url": http_url,
                "status": resp.status,
                "location": location or None,
                "redirects_to_https": redirects_to_https,
                "hsts_present": hsts_present,
            },
        )


class ClickjackingProcedure:
    """Observe whether the page can be framed (no anti-framing protection).

    Non-destructive GET. Hypothesis (weakness) = neither `X-Frame-Options` nor a
    CSP `frame-ancestors` directive is present, so the page is frameable.
    """

    key = "clickjacking"

    def applies_to(self, finding: Finding) -> bool:  # noqa: ARG002 - always applicable
        return True

    def probe(self, ctx: ProbeContext, finding: Finding) -> ProbeOutcome:
        resp = ctx.send("GET")
        if resp.status == 0:
            return ProbeOutcome(False, {"check": "clickjacking"}, error=resp.error or "request failed")
        xfo = resp.header("X-Frame-Options")
        csp = resp.header("Content-Security-Policy") or ""
        frame_ancestors = "frame-ancestors" in csp.lower()
        protected = bool(xfo) or frame_ancestors
        return ProbeOutcome(
            condition_met=not protected,  # weakness = frameable
            observation={
                "check": "clickjacking",
                "x_frame_options": xfo,
                "csp_frame_ancestors": frame_ancestors,
                "frameable": not protected,
                "status": resp.status,
            },
        )


class DirectoryListingProcedure:
    """Observe whether directory/auto-index listing is exposed.

    Non-destructive GET; only response signatures are inspected. Hypothesis
    (weakness) = the body looks like a server-generated directory index.
    """

    key = "directory_listing"
    _SIGNATURES = (
        "index of /",
        "directory listing for",
        "[to parent directory]",
        "parent directory</a>",
    )

    def applies_to(self, finding: Finding) -> bool:  # noqa: ARG002 - always applicable
        return True

    def probe(self, ctx: ProbeContext, finding: Finding) -> ProbeOutcome:
        resp = ctx.send("GET")
        if resp.status == 0:
            return ProbeOutcome(False, {"check": "directory_listing"}, error=resp.error or "request failed")
        body = resp.body.lower()
        signature = next((s for s in self._SIGNATURES if s in body), None)
        condition_met = signature is not None and 200 <= resp.status < 300
        return ProbeOutcome(
            condition_met=condition_met,
            observation={
                "check": "directory_listing",
                "status": resp.status,
                "listing_detected": condition_met,
                "signature": signature,
            },
        )


class ServerVersionProcedure:
    """Observe whether server/technology versions are disclosed in headers.

    Non-destructive GET. Hypothesis (weakness) = a version number is disclosed
    (e.g. `Server: nginx/1.2.3`) or a technology banner such as `X-Powered-By`
    is present.
    """

    key = "server_version"
    _VERSION_RE = re.compile(r"\d+\.\d+")
    _HEADERS = ("Server", "X-Powered-By", "X-AspNet-Version", "X-AspNetMvc-Version", "X-Generator")

    def applies_to(self, finding: Finding) -> bool:  # noqa: ARG002 - always applicable
        return True

    def probe(self, ctx: ProbeContext, finding: Finding) -> ProbeOutcome:
        resp = ctx.send("GET")
        if resp.status == 0:
            return ProbeOutcome(False, {"check": "server_version"}, error=resp.error or "request failed")
        disclosures = {h: resp.header(h) for h in self._HEADERS if resp.header(h)}
        version_disclosed = any(self._VERSION_RE.search(v) for v in disclosures.values())
        # A bare "Server: nginx" is not itself a finding; a version or a tech
        # banner (X-Powered-By / X-AspNet*) is.
        banner = any(k.lower() != "server" for k in disclosures)
        condition_met = version_disclosed or banner
        return ProbeOutcome(
            condition_met=condition_met,
            observation={
                "check": "server_version",
                "disclosures": disclosures,
                "version_disclosed": version_disclosed,
                "status": resp.status,
            },
        )


_DEFAULT_PROCEDURES = {
    SecurityHeaderProcedure.key: SecurityHeaderProcedure(),
    ReflectionProcedure.key: ReflectionProcedure(),
    HttpMethodProcedure.key: HttpMethodProcedure(),
    CookieFlagsProcedure.key: CookieFlagsProcedure(),
    CorsProcedure.key: CorsProcedure(),
    TlsRedirectProcedure.key: TlsRedirectProcedure(),
    ClickjackingProcedure.key: ClickjackingProcedure(),
    DirectoryListingProcedure.key: DirectoryListingProcedure(),
    ServerVersionProcedure.key: ServerVersionProcedure(),
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
            # automated check is NOT dropped — it is recorded as reported.
            return self._skipped(
                assessment,
                finding,
                reason="no automatic check for this finding type; reported for review",
                status="reported",
            )
        if not procedure.applies_to(finding):
            return self._skipped(
                assessment,
                finding,
                reason=f"procedure '{finding.check}' requires additional parameters",
                status="reported",
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
