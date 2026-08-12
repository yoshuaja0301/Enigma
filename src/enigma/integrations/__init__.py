"""Integration surfaces that let OpenClaw (or any client) connect to Enigma.

All surfaces wrap the same :class:`enigma.service.EnigmaService` facade:

* ``http_api``    — REST + webhook endpoint (stdlib HTTP server).
* ``mcp_server``  — Model Context Protocol server over stdio (for AI agents).
* ``client``      — a thin Python connector/SDK for the REST API.
"""

from __future__ import annotations

import json
from typing import Any, Dict, Optional
from urllib import request as _request
from urllib.error import HTTPError, URLError


def http_post_json(
    url: str,
    data: Dict[str, Any],
    token: Optional[str] = None,
    timeout: float = 30.0,
) -> Dict[str, Any]:
    """POST ``data`` as JSON and return the parsed JSON response."""

    payload = json.dumps(data).encode("utf-8")
    headers = {"Content-Type": "application/json", "Accept": "application/json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    req = _request.Request(url, data=payload, headers=headers, method="POST")
    return _read_json(req, timeout)


def http_get_json(url: str, token: Optional[str] = None, timeout: float = 30.0) -> Dict[str, Any]:
    headers = {"Accept": "application/json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    req = _request.Request(url, headers=headers, method="GET")
    return _read_json(req, timeout)


def _read_json(req, timeout: float) -> Dict[str, Any]:
    try:
        with _request.urlopen(req, timeout=timeout) as resp:
            body = resp.read().decode("utf-8", errors="replace")
    except HTTPError as exc:
        body = exc.read().decode("utf-8", errors="replace")
        try:
            parsed = json.loads(body)
        except json.JSONDecodeError:
            parsed = {"error": body}
        parsed.setdefault("status_code", exc.code)
        return parsed
    except (URLError, TimeoutError, OSError) as exc:
        return {"error": str(exc)}
    if not body:
        return {}
    return json.loads(body)


__all__ = ["http_post_json", "http_get_json"]
