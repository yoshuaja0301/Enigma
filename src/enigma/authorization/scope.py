"""Scope guard.

The scope guard answers a single question: *is this specific URL/host/path
allowed to be touched by this assessment?* It is deliberately conservative — an
unknown host, an excluded path or a disallowed port all deny the request.
"""

from __future__ import annotations

from dataclasses import dataclass
from urllib.parse import urlparse

from ..core.assessment import Scope

_DEFAULT_PORTS = {"http": 80, "https": 443}


@dataclass(frozen=True)
class ScopeDecision:
    allowed: bool
    reason: str

    def __bool__(self) -> bool:  # pragma: no cover - trivial
        return self.allowed


class ScopeGuard:
    """Validates URLs against an assessment :class:`Scope`."""

    def __init__(self, scope: Scope) -> None:
        self._scope = scope

    def check_url(self, url: str) -> ScopeDecision:
        parsed = urlparse(url)
        host = (parsed.hostname or "").lower()
        if not host:
            return ScopeDecision(False, "url has no host")

        if self._scope.allowed_hosts and host not in self._scope.allowed_hosts:
            return ScopeDecision(
                False,
                f"host '{host}' is not in allowed_hosts",
            )

        port = parsed.port if parsed.port is not None else _DEFAULT_PORTS.get(parsed.scheme.lower())
        if self._scope.allowed_ports and port not in self._scope.allowed_ports:
            return ScopeDecision(False, f"port '{port}' is not in allowed_ports")

        path = parsed.path or "/"
        for excluded in self._scope.excluded_paths:
            if self._path_matches(path, excluded):
                return ScopeDecision(False, f"path '{path}' matches excluded_path '{excluded}'")

        return ScopeDecision(True, "in scope")

    @staticmethod
    def _path_matches(path: str, excluded: str) -> bool:
        excluded = excluded.rstrip("/") or "/"
        if excluded == "/":
            return path == "/"
        return path == excluded or path.startswith(excluded + "/")
