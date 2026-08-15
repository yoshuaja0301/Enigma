import unittest

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
from enigma.reporting import render_dashboard_html, render_report_html, to_html
from enigma.verification.http import FakeTransport, HttpResponse


def build_results(title="Missing CSP"):
    assessment = Assessment(
        assessment_id="ASM-HTML",
        target=Target("https://authorized-target.example/"),
        authorization=Authorization(status=AuthorizationStatus.AUTHORIZED),
        scope=Scope(allowed_hosts=["authorized-target.example"]),
        profile=AssessmentProfile.SAFE_VERIFICATION,
    )
    transport = FakeTransport(default=HttpResponse(status=200, headers={"Server": "x"}, body="ok"))
    adapter = StaticOpenClawAdapter(
        [
            {
                "finding_id": "F-1",
                "title": title,
                "category": "missing_security_header",
                "confidence": 0.8,
                "target": {"path": "/a"},
                "check": "security_header",
                "parameters": {"header": "Content-Security-Policy"},
            }
        ]
    )
    return AssessmentController(transport=transport).run(assessment, adapter)


class HtmlReportTests(unittest.TestCase):
    def test_is_self_contained_document(self):
        html = to_html(build_results())
        self.assertTrue(html.lstrip().lower().startswith("<!doctype html>"))
        self.assertIn("<style>", html)  # inline CSS, no external assets
        self.assertNotIn("http://", html.split("<style>")[1].split("</style>")[0])  # no external css urls

    def test_contains_verdict_and_summary(self):
        html = to_html(build_results())
        self.assertIn("Confirmed", html)
        self.assertIn("Confirmation rate", html)
        self.assertIn("card confirmed", html)

    def test_escapes_ai_supplied_text(self):
        html = to_html(build_results(title="<script>alert('xss')</script>"))
        self.assertNotIn("<script>alert('xss')</script>", html)
        self.assertIn("&lt;script&gt;", html)

    def test_dashboard_empty_and_populated(self):
        empty = render_dashboard_html([])
        self.assertIn("No assessments", empty)
        populated = render_dashboard_html(
            [{"assessment_id": "ASM-1", "summary": {"confirmed": 2, "total": 3}}]
        )
        self.assertIn("ASM-1", populated)
        self.assertIn("/report/ASM-1", populated)

    def test_render_report_from_dict(self):
        report = {"summary": {"total": 0, "confirmation_rate": 0, "false_positive_rate": 0}, "results": []}
        html = render_report_html(report)
        self.assertIn("No findings were assessed.", html)


if __name__ == "__main__":
    unittest.main()
