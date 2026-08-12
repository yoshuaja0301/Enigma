"""End-to-end pipeline test against a real (local, authorized) HTTP server.

Spins up a throwaway server on 127.0.0.1 and runs the full controller pipeline
with the real urllib transport — exercising authorization, scope, verification,
evidence and OSSTMM mapping together.
"""

import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from enigma.agent.openclaw import StaticOpenClawAdapter
from enigma.controller import AssessmentController
from enigma.core.assessment import (
    Assessment,
    AssessmentProfile,
    Authorization,
    AuthorizationStatus,
    Scope,
)
from enigma.core.target import Target
from enigma.findings.model import Verdict


class _Handler(BaseHTTPRequestHandler):
    def log_message(self, *args):  # silence test output
        return

    def _send(self, extra_headers=None, body=b"hello"):
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        for key, value in (extra_headers or {}).items():
            self.send_header(key, value)
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        if self.path.startswith("/has-csp"):
            self._send({"Content-Security-Policy": "default-src 'self'"})
        elif self.path.startswith("/reflect"):
            # echo the raw query back (reflection signal)
            query = self.path.split("?", 1)[1] if "?" in self.path else ""
            self._send(body=f"you searched: {query}".encode())
        else:
            self._send()

    def do_OPTIONS(self):
        self.send_response(200)
        self.send_header("Allow", "GET, HEAD, OPTIONS, TRACE")
        self.end_headers()


class LocalPipelineTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
        cls.port = cls.server.server_address[1]
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()

    def _assessment(self):
        return Assessment(
            assessment_id="ASM-INT",
            target=Target(f"http://127.0.0.1:{self.port}/"),
            authorization=Authorization(status=AuthorizationStatus.AUTHORIZED),
            scope=Scope(allowed_hosts=["127.0.0.1"], allowed_ports=[self.port]),
            profile=AssessmentProfile.SAFE_VERIFICATION,
        )

    def _run(self, findings):
        controller = AssessmentController()  # real UrllibTransport
        return controller.run(self._assessment(), StaticOpenClawAdapter(findings))

    def test_missing_header_confirmed(self):
        results = self._run(
            [
                {
                    "finding_id": "F-CSP",
                    "check": "security_header",
                    "target": {"path": "/no-csp"},
                    "parameters": {"header": "Content-Security-Policy"},
                }
            ]
        )
        self.assertEqual(results[0].verdict, Verdict.CONFIRMED)
        self.assertTrue(results[0].reproducible)
        self.assertIsNotNone(results[0].evidence)
        self.assertEqual(results[0].methodology["name"], "OSSTMM")

    def test_present_header_not_confirmed(self):
        results = self._run(
            [
                {
                    "finding_id": "F-CSP2",
                    "check": "security_header",
                    "target": {"path": "/has-csp"},
                    "parameters": {"header": "Content-Security-Policy"},
                }
            ]
        )
        self.assertEqual(results[0].verdict, Verdict.NOT_CONFIRMED)

    def test_reflection_confirmed(self):
        results = self._run(
            [{"finding_id": "F-REF", "check": "reflection", "target": {"path": "/reflect"}, "parameters": {"param": "q"}}]
        )
        self.assertEqual(results[0].verdict, Verdict.CONFIRMED)

    def test_http_method_trace_confirmed(self):
        results = self._run(
            [{"finding_id": "F-TRACE", "check": "http_method", "target": {"path": "/"}, "parameters": {"method": "TRACE"}}]
        )
        self.assertEqual(results[0].verdict, Verdict.CONFIRMED)

    def test_out_of_scope_blocked(self):
        controller = AssessmentController()
        # scope only allows 127.0.0.1, but finding targets a foreign host path
        # via an assessment whose target is localhost; force scope mismatch by
        # narrowing allowed_ports.
        assessment = Assessment(
            assessment_id="ASM-INT2",
            target=Target(f"http://127.0.0.1:{self.port}/"),
            authorization=Authorization(status=AuthorizationStatus.AUTHORIZED),
            scope=Scope(allowed_hosts=["127.0.0.1"], allowed_ports=[self.port + 1]),
            profile=AssessmentProfile.SAFE_VERIFICATION,
        )
        results = controller.run(
            assessment,
            StaticOpenClawAdapter(
                [{"finding_id": "F-B", "check": "security_header", "parameters": {"header": "X-Frame-Options"}}]
            ),
        )
        self.assertTrue(results[0].blocked)


if __name__ == "__main__":
    unittest.main()
