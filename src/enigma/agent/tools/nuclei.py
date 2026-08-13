"""Parse Nuclei output into Enigma findings.

Nuclei emits one JSON object per line (``nuclei -jsonl``; older builds use
``-json``). A whole-file JSON array is also accepted, since that is how results
are often stored.

Each result becomes a finding. Where the template maps onto one of Enigma's safe
checks the finding carries ``check`` + ``parameters`` so it is verified
automatically; otherwise ``check`` is omitted and Enigma records it as
``reported`` for a human. Nuclei's own severity becomes the finding's
``confidence`` — a hypothesis, never evidence.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from .common import (
    clamp01,
    find_cookie_flag,
    find_header,
    loads_or_none,
    path_only,
    query_param,
    read_text,
    split_url,
)

# Nuclei severity is the tool's opinion — mapped into the hypothesis slot only.
_SEVERITY_CONFIDENCE = {
    "critical": 0.9,
    "high": 0.8,
    "medium": 0.65,
    "low": 0.5,
    "info": 0.3,
    "unknown": 0.3,
}

# Template-id / tag substrings that identify a check Enigma can verify.
_TEMPLATE_CHECKS = (
    ("clickjack", "clickjacking"),
    ("x-frame-options", "clickjacking"),
    ("dir-listing", "directory_listing"),
    ("directory-listing", "directory_listing"),
    ("directory-browsing", "directory_listing"),
    ("cors", "cors"),
    ("missing-security-headers", "security_header"),
    ("security-headers", "security_header"),
    ("http-missing-security-headers", "security_header"),
    ("hsts", "tls_redirect"),
    ("cookie", "cookie_flags"),
    ("version-disclosure", "server_version"),
    ("tech-detect", "server_version"),
    ("server-header", "server_version"),
)


def _severity(result: Dict[str, Any]) -> str:
    info = result.get("info") or {}
    return str(info.get("severity", "unknown")).strip().lower()


def _signals(result: Dict[str, Any]) -> str:
    """All the text worth pattern-matching for check inference."""

    info = result.get("info") or {}
    tags = info.get("tags")
    if isinstance(tags, list):
        tags = " ".join(str(t) for t in tags)
    extracted = result.get("extracted-results")
    if isinstance(extracted, list):
        extracted = " ".join(str(e) for e in extracted)
    parts = [
        result.get("template-id"),
        result.get("templateID"),
        info.get("name"),
        tags,
        result.get("matcher-name"),
        extracted,
    ]
    return " ".join(str(p) for p in parts if p).lower()


def _infer_check(result: Dict[str, Any], signals: str) -> Optional[str]:
    for needle, check in _TEMPLATE_CHECKS:
        if needle in signals:
            # 'cookie' alone is ambiguous unless a flag is identifiable.
            if check == "cookie_flags" and not find_cookie_flag(signals):
                continue
            return check
    return None


def _parameters(check: Optional[str], result: Dict[str, Any], signals: str) -> Dict[str, Any]:
    if check == "security_header":
        header = find_header(signals)
        return {"header": header} if header else {}
    if check == "cookie_flags":
        flag = find_cookie_flag(signals)
        return {"flag": flag} if flag else {}
    if check == "reflection":
        param = query_param(result.get("matched-at") or result.get("matched"))
        return {"param": param} if param else {}
    return {}


def parse_nuclei(source: Any) -> List[Dict[str, Any]]:
    """Parse Nuclei JSONL (or a JSON array) into raw Enigma findings."""

    text = read_text(source)
    results: List[Dict[str, Any]] = []

    stripped = text.strip()
    if stripped.startswith("["):
        import json

        try:
            loaded = json.loads(stripped)
            if isinstance(loaded, list):
                results = [r for r in loaded if isinstance(r, dict)]
        except json.JSONDecodeError:
            results = []
    if not results:
        for line in text.splitlines():
            line = line.strip()
            if not line:
                continue
            parsed = loads_or_none(line)
            if parsed is not None:
                results.append(parsed)

    findings: List[Dict[str, Any]] = []
    for index, result in enumerate(results, start=1):
        info = result.get("info") or {}
        template_id = str(result.get("template-id") or result.get("templateID") or f"result-{index}")
        matched = result.get("matched-at") or result.get("matched") or result.get("host")
        host, _ = split_url(matched)
        signals = _signals(result)
        check = _infer_check(result, signals)
        parameters = _parameters(check, result, signals)
        # A check whose required parameter could not be determined cannot be
        # verified — record it rather than run an under-specified probe.
        if check in ("security_header", "cookie_flags") and not parameters:
            check = None

        severity = _severity(result)
        finding: Dict[str, Any] = {
            "finding_id": f"NUCLEI-{index:04d}",
            "title": str(info.get("name") or template_id),
            "description": str(info.get("description") or "").strip(),
            "category": template_id,
            "confidence": clamp01(_SEVERITY_CONFIDENCE.get(severity, 0.3)),
            "target": {"path": path_only(matched)},
            "source": "nuclei",
            "tool": {
                "name": "nuclei",
                "template_id": template_id,
                "severity": severity,
                "matched_at": matched,
                "matcher_name": result.get("matcher-name"),
            },
        }
        if host:
            finding["target"]["host"] = host
        if check:
            finding["check"] = check
            if parameters:
                finding["parameters"] = parameters
        findings.append(finding)

    return findings
