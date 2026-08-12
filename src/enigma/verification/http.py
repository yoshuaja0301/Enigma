"""HTTP transport used by verification procedures.

Deliberately minimal and read-oriented. The transport is an injectable
interface so that:

* the CLI uses a real, timeout-bounded urllib transport;
* tests use a deterministic fake transport (no network);

and so procedures never construct their own network access outside the policy /
authorization gate.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, Optional, Protocol
from urllib import request as urllib_request
from urllib.error import HTTPError, URLError


@dataclass
class HttpResponse:
    status: int
    headers: Dict[str, str] = field(default_factory=dict)
    body: str = ""
    url: str = ""
    error: Optional[str] = None

    def header(self, name: str) -> Optional[str]:
        target = name.lower()
        for key, value in self.headers.items():
            if key.lower() == target:
                return value
        return None

    def has_header(self, name: str) -> bool:
        return self.header(name) is not None


class Transport(Protocol):
    """Anything that can perform a single HTTP request."""

    def request(
        self,
        method: str,
        url: str,
        headers: Optional[Dict[str, str]] = None,
        timeout: float = 10.0,
        max_body_bytes: int = 262_144,
    ) -> HttpResponse:
        ...


class UrllibTransport:
    """A real HTTP transport built on the standard library.

    It never follows unbounded redirects into out-of-scope hosts implicitly:
    redirects are surfaced via the ``Location`` header and status code so the
    caller (which already passed the scope gate for the requested URL) stays in
    control.
    """

    def __init__(self, user_agent: str = "Enigma/0.1 (+authorized-assessment)") -> None:
        self._user_agent = user_agent

    def request(
        self,
        method: str,
        url: str,
        headers: Optional[Dict[str, str]] = None,
        timeout: float = 10.0,
        max_body_bytes: int = 262_144,
    ) -> HttpResponse:
        req_headers = {"User-Agent": self._user_agent}
        if headers:
            req_headers.update(headers)
        req = urllib_request.Request(url=url, method=method.upper(), headers=req_headers)

        # Do not auto-follow redirects: we want to observe them, not chase them.
        opener = urllib_request.build_opener(_NoRedirect())
        try:
            with opener.open(req, timeout=timeout) as resp:
                body = resp.read(max_body_bytes)
                return HttpResponse(
                    status=resp.status,
                    headers=dict(resp.headers.items()),
                    body=body.decode("utf-8", errors="replace"),
                    url=resp.url or url,
                )
        except HTTPError as exc:  # non-2xx/3xx still carries headers + body
            body = b""
            try:
                body = exc.read(max_body_bytes)
            except Exception:  # pragma: no cover - best effort
                pass
            return HttpResponse(
                status=exc.code,
                headers=dict(exc.headers.items()) if exc.headers else {},
                body=body.decode("utf-8", errors="replace"),
                url=url,
            )
        except (URLError, TimeoutError, OSError) as exc:
            return HttpResponse(status=0, url=url, error=str(exc))


class _NoRedirect(urllib_request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: D401, ANN001
        return None  # do not follow


class FakeTransport:
    """Deterministic transport for tests and offline demonstration.

    Configure it with a callable or a fixed :class:`HttpResponse` keyed by
    ``(method, path)`` or by URL. Records every exchange for evidence tests.
    """

    def __init__(self, handler=None, default: Optional[HttpResponse] = None) -> None:
        self._handler = handler
        self._default = default or HttpResponse(status=200, body="", headers={})
        self.exchanges = []  # list of (method, url, headers)

    def request(
        self,
        method: str,
        url: str,
        headers: Optional[Dict[str, str]] = None,
        timeout: float = 10.0,  # noqa: ARG002
        max_body_bytes: int = 262_144,  # noqa: ARG002
    ) -> HttpResponse:
        self.exchanges.append((method.upper(), url, dict(headers or {})))
        if callable(self._handler):
            result = self._handler(method.upper(), url, headers or {})
            if result is not None:
                return result
        return self._default
