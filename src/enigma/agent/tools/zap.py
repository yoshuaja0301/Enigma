"""Parse OWASP ZAP JSON reports into Enigma findings.

ZAP's JSON report nests ``site[] -> alerts[] -> instances[]``. Each *instance*
becomes a finding, so a verdict is tied to a concrete URL rather than to an
alert covering many.

Alerts are matched to Enigma's safe checks primarily by ZAP's stable
``pluginid``, falling back to the alert name. ZAP's own ``confidence`` becomes
the finding's ``confidence`` — a hypothesis, never evidence; ``riskcode`` is
retained as provenance only.
"""

from __future__ import annotations

import json
from typing import Any, Dict, List, Optional, Tuple

from .common import (
    clamp01,
    find_cookie_flag,
    find_header,
    path_only,
    query_param,
    read_text,
    split_url,
)

# ZAP confidence: 0 False Positive, 1 Low, 2 Medium, 3 High.
_CONFIDENCE = {0: 0.1, 1: 0.4, 2: 0.65, 3: 0.85}
# ZAP riskcode: 0 Informational, 1 Low, 2 Medium, 3 High — provenance only.
_RISK_NAMES = {0: "informational", 1: "low", 2: "medium", 3: "high"}

# Stable ZAP plugin ids → (check, fixed parameters). None means "infer".
_PLUGIN_CHECKS: Dict[str, Tuple[str, Optional[Dict[str, Any]]]] = {
    "10038": ("security_header", {"header": "Content-Security-Policy"}),
    "10035": ("security_header", {"header": "Strict-Transport-Security"}),
    "10021": ("security_header", {"header": "X-Content-Type-Options"}),
    "10020": ("clickjacking", {}),
    "10010": ("cookie_flags", {"flag": "HttpOnly"}),
    "10011": ("cookie_flags", {"flag": "Secure"}),
    "10054": ("cookie_flags", {"flag": "SameSite"}),
    "10033": ("directory_listing", {}),
    "10036": ("server_version", {}),
    "10037": ("server_version", {}),
    "10098": ("cors", {}),
}

# Fallback: substrings of the alert name.
_NAME_CHECKS = (
    ("anti-clickjacking", "clickjacking"),
    ("clickjacking", "clickjacking"),
    ("directory browsing", "directory_listing"),
    ("directory listing", "directory_listing"),
    ("cross-domain misconfiguration", "cors"),
    ("cors", "cors"),
    ("leaks version", "server_version"),
    ("server leaks", "server_version"),
    ("cookie", "cookie_flags"),
    ("header not set", "security_header"),
    ("header missing", "security_header"),
    ("reflected", "reflection"),
)


def _as_int(value: Any, default: int = 0) -> int:
    try:
        return int(str(value).strip())
    except (TypeError, ValueError):
        return default


def _sites(report: Dict[str, Any]) -> List[Dict[str, Any]]:
    sites = report.get("site")
    if sites is None:
        # Some exports place alerts at the top level.
        alerts = report.get("alerts")
        return [{"alerts": alerts}] if isinstance(alerts, list) else []
    if isinstance(sites, dict):
        return [sites]
    return [s for s in sites if isinstance(s, dict)]


def _infer_check(plugin_id: str, name: str) -> Tuple[Optional[str], Dict[str, Any]]:
    mapped = _PLUGIN_CHECKS.get(plugin_id)
    if mapped:
        check, params = mapped
        return check, dict(params or {})

    lowered = (name or "").lower()
    for needle, check in _NAME_CHECKS:
        if needle in lowered:
            if check == "security_header":
                header = find_header(lowered)
                return ("security_header", {"header": header}) if header else (None, {})
            if check == "cookie_flags":
                flag = find_cookie_flag(lowered)
                return ("cookie_flags", {"flag": flag}) if flag else (None, {})
            return check, {}
    return None, {}


def parse_zap(source: Any) -> List[Dict[str, Any]]:
    """Parse an OWASP ZAP JSON report into raw Enigma findings."""

    text = read_text(source)
    try:
        report = json.loads(text)
    except json.JSONDecodeError as exc:
        raise ValueError(f"could not parse ZAP JSON report: {exc}") from exc
    if not isinstance(report, dict):
        raise ValueError("ZAP report must be a JSON object")

    findings: List[Dict[str, Any]] = []
    index = 0

    for site in _sites(report):
        site_host = str(site.get("@host") or "").lower() or None
        for alert in site.get("alerts") or []:
            if not isinstance(alert, dict):
                continue
            plugin_id = str(alert.get("pluginid") or alert.get("pluginId") or "").strip()
            name = str(alert.get("alert") or alert.get("name") or "").strip()
            check, parameters = _infer_check(plugin_id, name)
            confidence = clamp01(_CONFIDENCE.get(_as_int(alert.get("confidence"), 2), 0.65))
            riskcode = _as_int(alert.get("riskcode"), 0)

            instances = alert.get("instances")
            if not isinstance(instances, list) or not instances:
                instances = [{}]

            for instance in instances:
                if not isinstance(instance, dict):
                    instance = {}
                index += 1
                uri = instance.get("uri") or site.get("@name")
                host, _ = split_url(uri)

                params = dict(parameters)
                if check == "reflection" and not params:
                    param = instance.get("param") or query_param(uri)
                    if param:
                        params["param"] = str(param)
                    else:
                        check = None

                finding: Dict[str, Any] = {
                    "finding_id": f"ZAP-{index:04d}",
                    "title": name or f"ZAP alert {plugin_id}",
                    "description": str(alert.get("desc") or "").strip(),
                    "category": f"zap-{plugin_id}" if plugin_id else "zap",
                    "confidence": confidence,
                    "target": {"path": path_only(uri)},
                    "source": "zap",
                    "tool": {
                        "name": "zap",
                        "plugin_id": plugin_id,
                        "risk": _RISK_NAMES.get(riskcode, "unknown"),
                        "uri": uri,
                        "cweid": alert.get("cweid"),
                        "evidence": instance.get("evidence") or None,
                    },
                }
                target_host = host or site_host
                if target_host:
                    finding["target"]["host"] = target_host
                if check:
                    finding["check"] = check
                    if params:
                        finding["parameters"] = params
                findings.append(finding)

    return findings
