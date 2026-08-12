"""Helpers to talk to a real OpenClaw agent.

Two directions:

* **Outbound** — describe the target/scope to OpenClaw so it can propose
  findings: :func:`build_openclaw_request` (a JSON payload for an HTTP service)
  and :func:`build_openclaw_prompt` (a text prompt for an LLM-style agent).
* **Inbound** — turn whatever OpenClaw returns (a list, an object wrapping a
  ``findings`` array, or LLM text possibly wrapped in a code fence) into the raw
  finding dicts Enigma's normalizer understands: :func:`parse_openclaw_findings`.

Enigma only tells OpenClaw which **safe verification checks** it can actually
prove, so proposals stay verifiable. OpenClaw never receives (or influences)
authorization — that stays entirely on the Enigma side.
"""

from __future__ import annotations

import json
from typing import Any, Dict, List

from ..core.assessment import Assessment
from ..findings.normalizer import KNOWN_CHECKS

# Per-check parameter hints, surfaced to OpenClaw so its proposals are runnable.
_CHECK_PARAMS = {
    "security_header": {"header": "the security header expected to be present, e.g. Content-Security-Policy"},
    "reflection": {"param": "the query parameter to test for reflection, e.g. q"},
    "http_method": {"method": "the HTTP method to test for, e.g. TRACE"},
}


def build_openclaw_request(assessment: Assessment) -> Dict[str, Any]:
    """A structured payload describing the target for an HTTP OpenClaw service."""

    return {
        "assessment_id": assessment.assessment_id,
        "target": {"url": assessment.target.url, "host": assessment.target.host},
        "scope": {
            "allowed_hosts": assessment.scope.allowed_hosts,
            "excluded_paths": assessment.scope.excluded_paths,
        },
        "profile": assessment.profile.value,
        # Only these checks can be verified — ask OpenClaw to stay within them.
        "supported_checks": sorted(KNOWN_CHECKS),
        "finding_schema": {
            "finding_id": "string",
            "title": "string",
            "category": "string",
            "confidence": "0.0-1.0",
            "target": {"path": "string"},
            "check": f"one of: {', '.join(sorted(KNOWN_CHECKS))}",
            "parameters": _CHECK_PARAMS,
        },
    }


def build_openclaw_prompt(assessment: Assessment) -> str:
    """A text prompt instructing an LLM-style OpenClaw to emit findings JSON."""

    request = build_openclaw_request(assessment)
    return (
        "You are OpenClaw, an AI web-security assessor. Propose POTENTIAL findings "
        "for the authorized target below. You do not decide authorization or scope, "
        "and you must only propose findings that map to one of the supported checks "
        "so they can be independently verified.\n\n"
        f"Target: {assessment.target.url}\n"
        f"In-scope hosts: {', '.join(assessment.scope.allowed_hosts) or assessment.target.host}\n"
        f"Excluded paths: {', '.join(assessment.scope.excluded_paths) or '(none)'}\n"
        f"Supported checks: {', '.join(sorted(KNOWN_CHECKS))}\n\n"
        "Respond with ONLY a JSON array of finding objects using this schema:\n"
        f"{json.dumps(request['finding_schema'], indent=2)}\n"
    )


def coerce_findings(data: Any) -> List[Dict[str, Any]]:
    """Normalize container shapes to a plain list of finding dicts."""

    if isinstance(data, dict):
        data = data["findings"] if "findings" in data else [data]
    if not isinstance(data, list):
        raise ValueError("findings must be a list or an object with a 'findings' array")
    return [dict(item) for item in data]


def parse_openclaw_findings(payload: Any) -> List[Dict[str, Any]]:
    """Parse OpenClaw output (dict, list, or LLM text) into finding dicts."""

    if isinstance(payload, (list, dict)):
        return coerce_findings(payload)
    if isinstance(payload, (bytes, bytearray)):
        payload = payload.decode("utf-8", errors="replace")
    if not isinstance(payload, str):
        raise ValueError(f"unsupported OpenClaw payload type: {type(payload).__name__}")
    return coerce_findings(_extract_json(payload))


def _extract_json(text: str) -> Any:
    text = text.strip()
    # Strip a leading/trailing markdown code fence if present.
    if text.startswith("```"):
        lines = text.splitlines()
        if lines and lines[0].startswith("```"):
            lines = lines[1:]
        if lines and lines[-1].strip().startswith("```"):
            lines = lines[:-1]
        text = "\n".join(lines).strip()
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        pass
    # Fall back to locating the first JSON array or object in the text.
    for opener, closer in (("[", "]"), ("{", "}")):
        start = text.find(opener)
        end = text.rfind(closer)
        if start != -1 and end > start:
            try:
                return json.loads(text[start : end + 1])
            except json.JSONDecodeError:
                continue
    raise ValueError("could not parse JSON from OpenClaw output")
