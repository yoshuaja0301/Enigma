import json
import unittest

from enigma.core.assessment import (
    Assessment,
    AssessmentProfile,
    Authorization,
    AuthorizationStatus,
    Scope,
)
from enigma.core.target import Target
from enigma.agent.openclaw import StaticOpenClawAdapter
from enigma.controller import AssessmentController
from enigma.reporting import summarize, to_json, to_markdown
from enigma.verification.http import FakeTransport, HttpResponse


def build_results():
    target = Target("https://authorized-target.example/")
    assessment = Assessment(
        assessment_id="ASM-REP",
        target=target,
        authorization=Authorization(status=AuthorizationStatus.AUTHORIZED),
        scope=Scope(allowed_hosts=["authorized-target.example"]),
        profile=AssessmentProfile.SAFE_VERIFICATION,
    )
    # No CSP header -> the CSP finding will be CONFIRMED.
    transport = FakeTransport(default=HttpResponse(status=200, headers={"Server": "x"}, body="page"))
    adapter = StaticOpenClawAdapter(
        [
            {
                "finding_id": "F-1",
                "category": "missing_security_header",
                "confidence": 0.8,
                "target": {"path": "/a"},
                "check": "security_header",
                "parameters": {"header": "Content-Security-Policy"},
            },
            {"finding_id": "F-2", "category": "business_logic", "confidence": 0.6, "target": {"path": "/b"}},
        ]
    )
    controller = AssessmentController(transport=transport)
    return controller.run(assessment, adapter)


class ReportingTests(unittest.TestCase):
    def setUp(self):
        self.results = build_results()

    def test_summary_counts(self):
        summary = summarize(self.results)
        self.assertEqual(summary.total, 2)
        self.assertEqual(summary.confirmed, 1)
        self.assertEqual(summary.inconclusive, 1)

    def test_json_report_parses(self):
        payload = json.loads(to_json(self.results))
        self.assertIn("summary", payload)
        self.assertEqual(len(payload["results"]), 2)
        self.assertEqual(payload["results"][0]["methodology"]["name"], "OSSTMM")

    def test_markdown_report_has_headings(self):
        md = to_markdown(self.results)
        self.assertIn("# Enigma Assessment Report", md)
        self.assertIn("CONFIRMED", md)


if __name__ == "__main__":
    unittest.main()
