"""Shared helpers for tool-output parsers."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, Optional, Tuple
from urllib.parse import urlsplit

# Security headers Enigma can verify, keyed by the lower-case name a tool is
# likely to mention. Values are the canonical header spelling.
SECURITY_HEADERS: Dict[str, str] = {
    "content-security-policy": "Content-Security-Policy",
    "csp": "Content-Security-Policy",
    "strict-transport-security": "Strict-Transport-Security",
    "hsts": "Strict-Transport-Security",
    "x-content-type-options": "X-Content-Type-Options",
    "x-frame-options": "X-Frame-Options",
    "referrer-policy": "Referrer-Policy",
    "permissions-policy": "Permissions-Policy",
    "x-xss-protection": "X-XSS-Protection",
}

COOKIE_FLAGS: Dict[str, str] = {
    "httponly": "HttpOnly",
    "http only": "HttpOnly",
    "secure": "Secure",
    "samesite": "SameSite",
    "same site": "SameSite",
}


def read_text(source: Any) -> str:
    """Accept a path, an open file object, bytes, or raw text."""

    if hasattr(source, "read"):
        data = source.read()
        return data.decode("utf-8", errors="replace") if isinstance(data, bytes) else data
    if isinstance(source, (bytes, bytearray)):
        return bytes(source).decode("utf-8", errors="replace")
    text = str(source)
    # Heuristic: treat it as a path only when it looks like one and names an
    # existing *file*. An empty string resolves to '.', hence the strip check.
    if text.strip() and "\n" not in text and len(text) < 4096:
        path = Path(text)
        if path.is_file():
            return path.read_text(encoding="utf-8", errors="replace")
    return text


def split_url(url: Optional[str]) -> Tuple[Optional[str], str]:
    """Return (host, path) for a tool-reported URL; path defaults to '/'."""

    if not url:
        return None, "/"
    parts = urlsplit(str(url))
    if not parts.scheme and not parts.netloc:
        # A bare path such as "/admin/".
        path = parts.path or "/"
        return None, path if path.startswith("/") else "/" + path
    path = parts.path or "/"
    if parts.query:
        path = f"{path}?{parts.query}"
    return (parts.hostname.lower() if parts.hostname else None), path


def path_only(url: Optional[str]) -> str:
    """Path without a query string — what verification procedures target."""

    _, path = split_url(url)
    return path.split("?", 1)[0] or "/"


def query_param(url: Optional[str]) -> Optional[str]:
    """First query parameter name in a URL, if any (used for reflection checks)."""

    if not url:
        return None
    query = urlsplit(str(url)).query
    if not query:
        return None
    first = query.split("&", 1)[0]
    name = first.split("=", 1)[0].strip()
    return name or None


def find_header(text: str) -> Optional[str]:
    """Canonical security-header name mentioned in a free-text string."""

    lowered = (text or "").lower()
    # Longest key first so 'content-security-policy' wins over 'csp'.
    for key in sorted(SECURITY_HEADERS, key=len, reverse=True):
        if key in lowered:
            return SECURITY_HEADERS[key]
    return None


def find_cookie_flag(text: str) -> Optional[str]:
    lowered = (text or "").lower()
    for key in sorted(COOKIE_FLAGS, key=len, reverse=True):
        if key in lowered:
            return COOKIE_FLAGS[key]
    return None


def clamp01(value: float) -> float:
    return max(0.0, min(1.0, float(value)))


def loads_or_none(line: str) -> Optional[Dict[str, Any]]:
    try:
        parsed = json.loads(line)
    except json.JSONDecodeError:
        return None
    return parsed if isinstance(parsed, dict) else None
