import json
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from enigma.agent.openclaw import (
    CallableOpenClawAdapter,
    HttpOpenClawAdapter,
    StaticOpenClawAdapter,
)
from enigma.agent.prompt import (
    build_openclaw_prompt,
    coerce_findings,
    parse_openclaw_findings,
)
from enigma.controller import AssessmentController
from enigma.core.assessment import (
    Assessment,
    AssessmentProfile,
    Authorization,
    AuthorizationStatus,
    Scope,
)
from enigma.core.target import Target
from enigma.verification.http import FakeTransport, HttpResponse


def assessment():
    return Assessment(
        assessment_id="ASM-ADAPTER",
        target=Target("https://authorized-target.example/"),
        authorization=Authorization(status=AuthorizationStatus.AUTHORIZED),
        scope=Scope(allowed_hosts=["authorized-target.example"]),
        profile=AssessmentProfile.SAFE_VERIFICATION,
    )


FINDING = {
    "finding_id": "OC-1",
    "title": "Missing CSP",
    "check": "security_header",
    "target": {"path": "/search"},
    "parameters": {"header": "Content-Security-Policy"},
}


class CoerceAndParseTests(unittest.TestCase):
    def test_coerce_variants(self):
        self.assertEqual(len(coerce_findings([FINDING])), 1)
        self.assertEqual(len(coerce_findings({"findings": [FINDING, FINDING]})), 2)
        self.assertEqual(len(coerce_findings(FINDING)), 1)  # single object

    def test_parse_raw_json_array(self):
        out = parse_openclaw_findings(json.dumps([FINDING]))
        self.assertEqual(out[0]["finding_id"], "OC-1")

    def test_parse_code_fenced_json(self):
        text = "```json\n" + json.dumps({"findings": [FINDING]}) + "\n```"
        out = parse_openclaw_findings(text)
        self.assertEqual(len(out), 1)

    def test_parse_json_with_surrounding_prose(self):
        text = "Here are the findings I propose:\n" + json.dumps([FINDING]) + "\nHope that helps!"
        out = parse_openclaw_findings(text)
        self.assertEqual(out[0]["check"], "security_header")

    def test_parse_invalid_raises(self):
        with self.assertRaises(ValueError):
            parse_openclaw_findings("no json here")

    def test_prompt_mentions_target_and_checks(self):
        prompt = build_openclaw_prompt(assessment())
        self.assertIn("authorized-target.example", prompt)
        self.assertIn("security_header", prompt)


class CallableAdapterTests(unittest.TestCase):
    def test_llm_style_end_to_end(self):
        # A stub "model": ignores the prompt, returns fenced JSON findings.
        def complete(prompt: str) -> str:
            self.assertIn("OpenClaw", prompt)
            return "```json\n" + json.dumps([FINDING]) + "\n```"

        adapter = CallableOpenClawAdapter(complete)
        transport = FakeTransport(default=HttpResponse(status=200, headers={"Server": "x"}, body="ok"))
        results = AssessmentController(transport=transport).run(assessment(), adapter)
        self.assertEqual(results[0].verdict.value, "CONFIRMED")


class HttpAdapterTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        payload = json.dumps({"findings": [FINDING]}).encode()

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *a):
                return

            def do_POST(self):
                length = int(self.headers.get("Content-Length", 0) or 0)
                self.rfile.read(length)
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(payload)

        cls.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        cls.port = cls.server.server_address[1]
        threading.Thread(target=cls.server.serve_forever, daemon=True).start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()

    def test_fetches_findings_from_http_openclaw(self):
        adapter = HttpOpenClawAdapter(f"http://127.0.0.1:{self.port}/findings")
        findings = adapter.get_findings(assessment())
        self.assertEqual(findings[0]["finding_id"], "OC-1")


if __name__ == "__main__":
    unittest.main()
