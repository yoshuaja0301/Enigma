"""Parse WhatWeb JSON output into Enigma findings.

WhatWeb (``whatweb --log-json=out.json``) emits one JSON object per target —
either as JSON Lines or a JSON array depending on version. Both are accepted.

**Most of what WhatWeb reports is not a finding.** ``Title``, ``Country``, ``IP``,
``HTML5`` and friends are inventory, not security observations; emitting them as
findings would bury the real ones in noise. So a plugin becomes a finding only
when it is security-relevant:

1. it reports a **version** (any plugin) — a version disclosure, verifiable via
   the ``server_version`` check; or
2. it is a known **disclosure header** (``HTTPServer``, ``X-Powered-By``, …); or
3. it names a technology whose mere identification is worth recording, in which
   case it is kept as ``reported``.

Everything else is skipped, and the count of skipped plugins is preserved in the
finding's provenance so the omission is visible rather than silent.
"""

from __future__ import annotations

import json
import re
from typing import Any, Dict, Iterable, List, Optional

from .common import clamp01, path_only, read_text, split_url

# Plugins whose presence is itself a version/technology disclosure.
DISCLOSURE_PLUGINS = {
    "httpserver",
    "x-powered-by",
    "powered-by",
    "poweredby",
    "server",
    "via-proxy",
    "x-aspnet-version",
    "x-aspnetmvc-version",
    "x-generator",
    "generator",
}

# Pure inventory/metadata — never a finding.
METADATA_PLUGINS = {
    "title", "country", "ip", "html5", "script", "meta-author", "meta-refresh-redirect",
    "uncommonheaders", "email", "cookies", "frame", "probablylinux", "opensearch",
    "detected-phrase", "index-of", "redirectlocation", "content-language", "charset",
}

_VERSION_RE = re.compile(r"\b\d+(?:\.\d+)+\b")


def _plugin_versions(payload: Any) -> List[str]:
    """Versions a WhatWeb plugin reports, from `version` or parsed from `string`."""

    if not isinstance(payload, dict):
        return []
    versions: List[str] = []
    for value in payload.get("version") or []:
        text = str(value).strip()
        if text:
            versions.append(text)
    if not versions:
        for value in payload.get("string") or []:
            match = _VERSION_RE.search(str(value))
            if match:
                versions.append(match.group(0))
    return versions


def _plugin_strings(payload: Any) -> List[str]:
    if not isinstance(payload, dict):
        return []
    return [str(v).strip() for v in (payload.get("string") or []) if str(v).strip()]


def _entries(text: str) -> List[Dict[str, Any]]:
    stripped = text.strip()
    if not stripped:
        return []
    if stripped.startswith("["):
        try:
            loaded = json.loads(stripped)
        except json.JSONDecodeError:
            loaded = None
        if isinstance(loaded, list):
            return [e for e in loaded if isinstance(e, dict)]
    entries: List[Dict[str, Any]] = []
    for line in stripped.splitlines():
        line = line.strip().rstrip(",")
        if not line or line in ("[", "]"):
            continue
        try:
            parsed = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(parsed, dict):
            entries.append(parsed)
    return entries


def parse_whatweb(source: Any) -> List[Dict[str, Any]]:
    """Parse WhatWeb JSON (JSONL or array) into raw Enigma findings."""

    entries = _entries(read_text(source))
    findings: List[Dict[str, Any]] = []
    index = 0

    for entry in entries:
        target = entry.get("target") or entry.get("uri") or ""
        host, _ = split_url(target)
        path = path_only(target)
        plugins = entry.get("plugins")
        if not isinstance(plugins, dict):
            continue

        skipped: List[str] = []
        for name, payload in plugins.items():
            key = str(name).strip().lower()
            if key in METADATA_PLUGINS:
                skipped.append(str(name))
                continue

            versions = _plugin_versions(payload)
            strings = _plugin_strings(payload)
            is_disclosure = key in DISCLOSURE_PLUGINS

            if not versions and not is_disclosure:
                # A technology identified without a version: recorded, not verified.
                if strings:
                    index += 1
                    findings.append({
                        "finding_id": f"WHATWEB-{index:04d}",
                        "title": f"Technology identified: {name}",
                        "description": "; ".join(strings)[:400],
                        "category": f"whatweb-{key}",
                        "confidence": 0.4,
                        "target": ({"path": path, "host": host} if host else {"path": path}),
                        "source": "whatweb",
                        "tool": {"name": "whatweb", "plugin": str(name), "target": target},
                    })
                else:
                    skipped.append(str(name))
                continue

            index += 1
            detail = ", ".join(versions) if versions else "; ".join(strings)
            finding: Dict[str, Any] = {
                "finding_id": f"WHATWEB-{index:04d}",
                "title": f"{name} discloses version/technology"
                + (f": {detail}" if detail else ""),
                "description": "; ".join(strings)[:400],
                "category": "version-disclosure",
                "confidence": clamp01(0.7 if versions else 0.55),
                "target": ({"path": path, "host": host} if host else {"path": path}),
                # Version/technology disclosure is observable in response headers.
                "check": "server_version",
                "source": "whatweb",
                "tool": {
                    "name": "whatweb",
                    "plugin": str(name),
                    "versions": versions,
                    "target": target,
                },
            }
            findings.append(finding)

        if skipped and findings:
            # Record what was intentionally not turned into a finding.
            findings[-1]["tool"]["skipped_metadata_plugins"] = sorted(set(skipped))

    return findings
