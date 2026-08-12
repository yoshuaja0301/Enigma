"""REST + webhook HTTP API for Enigma (standard library only).

Endpoints
---------
GET  /health                 liveness + which safety features are enabled
POST /validate               {assessment}                     -> gate decision
POST /verify                 {assessment, findings, callback_url?} -> report
POST /webhook/openclaw       {assessment, findings, callback_url?} -> report
GET  /results/{assessment_id}                                 -> stored report

Auth
----
If a token is configured (constructor arg or ``ENIGMA_API_TOKEN``), every route
except ``/health`` requires ``Authorization: Bearer <token>``.

Callback (outbound webhook)
---------------------------
If ``callback_url`` is supplied on a verify/webhook request, the resulting report
is also POSTed there (best-effort) so OpenClaw can receive results asynchronously.
"""

from __future__ import annotations

import json
import os
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Dict, Optional

from ..service import EnigmaService, ServerScopeError
from . import http_post_json


def create_server(
    host: str,
    port: int,
    service: EnigmaService,
    token: Optional[str] = None,
) -> ThreadingHTTPServer:
    handler = _make_handler(service, token)
    return ThreadingHTTPServer((host, port), handler)


def run_server(
    host: str = "127.0.0.1",
    port: int = 8737,
    service: Optional[EnigmaService] = None,
    token: Optional[str] = None,
) -> None:  # pragma: no cover - blocking loop
    service = service or EnigmaService()
    token = token or os.environ.get("ENIGMA_API_TOKEN")
    server = create_server(host, port, service, token)
    print(f"Enigma API listening on http://{host}:{port}  (auth={'on' if token else 'off'}, "
          f"allowlist={'on' if service.allowlist_enabled else 'off'})")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.shutdown()
        server.server_close()


def _make_handler(service: EnigmaService, token: Optional[str]):
    class Handler(BaseHTTPRequestHandler):
        server_version = "Enigma/0.1"

        def log_message(self, *args):  # keep the API quiet by default
            return

        # -- helpers ------------------------------------------------- #
        def _send(self, status: int, payload: Dict[str, Any]) -> None:
            body = json.dumps(payload).encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def _authorized(self) -> bool:
            if not token:
                return True
            header = self.headers.get("Authorization", "")
            return header == f"Bearer {token}"

        def _read_body(self) -> Optional[Dict[str, Any]]:
            length = int(self.headers.get("Content-Length", 0) or 0)
            if length == 0:
                return {}
            raw = self.rfile.read(length)
            try:
                return json.loads(raw.decode("utf-8"))
            except json.JSONDecodeError:
                return None

        # -- routing ------------------------------------------------- #
        def do_GET(self) -> None:
            if self.path == "/health":
                self._send(
                    200,
                    {
                        "status": "ok",
                        "service": "enigma",
                        "auth_required": bool(token),
                        "allowlist_enabled": service.allowlist_enabled,
                    },
                )
                return
            if not self._authorized():
                self._send(401, {"error": "unauthorized"})
                return
            if self.path.startswith("/results/"):
                assessment_id = self.path[len("/results/"):]
                report = service.get_result(assessment_id)
                if report is None:
                    self._send(404, {"error": f"no result for {assessment_id!r}"})
                else:
                    self._send(200, report)
                return
            self._send(404, {"error": "not found"})

        def do_POST(self) -> None:
            if not self._authorized():
                self._send(401, {"error": "unauthorized"})
                return

            body = self._read_body()
            if body is None:
                self._send(400, {"error": "invalid JSON body"})
                return

            if self.path == "/validate":
                self._handle_validate(body)
            elif self.path in ("/verify", "/webhook/openclaw"):
                self._handle_verify(body)
            else:
                self._send(404, {"error": "not found"})

        # -- handlers ------------------------------------------------ #
        def _assessment_of(self, body: Dict[str, Any]) -> Dict[str, Any]:
            # Accept either {"assessment": {...}} or the assessment inline.
            return body.get("assessment", body)

        def _handle_validate(self, body: Dict[str, Any]) -> None:
            try:
                result = service.validate(self._assessment_of(body))
            except ServerScopeError as exc:
                self._send(403, {"error": str(exc)})
            except (ValueError, KeyError) as exc:
                self._send(400, {"error": str(exc)})
            else:
                self._send(200, result)

        def _handle_verify(self, body: Dict[str, Any]) -> None:
            try:
                report = service.verify(self._assessment_of(body), body.get("findings"))
            except ServerScopeError as exc:
                self._send(403, {"error": str(exc)})
                return
            except (ValueError, KeyError) as exc:
                self._send(400, {"error": str(exc)})
                return

            callback_url = body.get("callback_url")
            if callback_url:
                report = dict(report)
                report["callback"] = _deliver_callback(callback_url, report)
            self._send(200, report)

    return Handler


def _deliver_callback(url: str, report: Dict[str, Any]) -> Dict[str, Any]:
    """Best-effort outbound webhook to an OpenClaw callback URL."""

    try:
        http_post_json(url, {"event": "verification_complete", "report": report}, timeout=15.0)
        return {"delivered": True, "url": url}
    except Exception as exc:  # pragma: no cover - network dependent
        return {"delivered": False, "url": url, "error": str(exc)}
