"""Unit tests for clickjacking, directory_listing and server_version."""

import unittest

from enigma.core.assessment import (
    Assessment,
    AssessmentProfile,
    Authorization,
    AuthorizationStatus,
    Scope,
)
from enigma.core.target import Target
from enigma.findings.model import Finding, Verdict
from enigma.verification.engine import VerificationEngine
from enigma.verification.http import FakeTransport, HttpResponse


def assessment():
    return Assessment(
        assessment_id="ASM-RECON",
        target=Target("https://authorized-target.example/"),
        authorization=Authorization(status=AuthorizationStatus.AUTHORIZED),
        scope=Scope(allowed_hosts=["authorized-target.example"]),
        profile=AssessmentProfile.SAFE_VERIFICATION,
    )


def verify(transport, finding):
    return VerificationEngine(transport=transport).verify(assessment(), finding)


class ClickjackingTests(unittest.TestCase):
    def test_frameable_is_confirmed(self):
        t = FakeTransport(default=HttpResponse(status=200, headers={"Server": "x"}))
        r = verify(t, Finding(finding_id="K1", check="clickjacking", target_path="/"))
        self.assertEqual(r.verdict, Verdict.CONFIRMED)
        self.assertTrue(r.observations[0]["frameable"])

    def test_x_frame_options_protects(self):
        t = FakeTransport(default=HttpResponse(status=200, headers={"X-Frame-Options": "DENY"}))
        r = verify(t, Finding(finding_id="K2", check="clickjacking", target_path="/"))
        self.assertEqual(r.verdict, Verdict.NOT_CONFIRMED)

    def test_csp_frame_ancestors_protects(self):
        t = FakeTransport(default=HttpResponse(
            status=200, headers={"Content-Security-Policy": "default-src 'self'; frame-ancestors 'none'"}))
        r = verify(t, Finding(finding_id="K3", check="clickjacking", target_path="/"))
        self.assertEqual(r.verdict, Verdict.NOT_CONFIRMED)
        self.assertTrue(r.observations[0]["csp_frame_ancestors"])


class DirectoryListingTests(unittest.TestCase):
    def test_index_of_is_confirmed(self):
        t = FakeTransport(default=HttpResponse(status=200, body="<h1>Index of /files</h1><a>..</a>"))
        r = verify(t, Finding(finding_id="D1", check="directory_listing", target_path="/files/"))
        self.assertEqual(r.verdict, Verdict.CONFIRMED)
        self.assertEqual(r.observations[0]["signature"], "index of /")

    def test_normal_page_not_confirmed(self):
        t = FakeTransport(default=HttpResponse(status=200, body="<html><body>Welcome</body></html>"))
        r = verify(t, Finding(finding_id="D2", check="directory_listing", target_path="/"))
        self.assertEqual(r.verdict, Verdict.NOT_CONFIRMED)

    def test_signature_on_404_not_confirmed(self):
        # A 404 body mentioning the phrase is not an exposed listing.
        t = FakeTransport(default=HttpResponse(status=404, body="index of / not found"))
        r = verify(t, Finding(finding_id="D3", check="directory_listing", target_path="/x/"))
        self.assertEqual(r.verdict, Verdict.NOT_CONFIRMED)


class ServerVersionTests(unittest.TestCase):
    def test_version_in_server_header_confirmed(self):
        t = FakeTransport(default=HttpResponse(status=200, headers={"Server": "nginx/1.18.0"}))
        r = verify(t, Finding(finding_id="V1", check="server_version", target_path="/"))
        self.assertEqual(r.verdict, Verdict.CONFIRMED)
        self.assertTrue(r.observations[0]["version_disclosed"])

    def test_x_powered_by_confirmed(self):
        t = FakeTransport(default=HttpResponse(status=200, headers={"X-Powered-By": "PHP"}))
        r = verify(t, Finding(finding_id="V2", check="server_version", target_path="/"))
        self.assertEqual(r.verdict, Verdict.CONFIRMED)

    def test_bare_server_name_not_confirmed(self):
        # "Server: nginx" with no version and no tech banner is not a finding.
        t = FakeTransport(default=HttpResponse(status=200, headers={"Server": "nginx"}))
        r = verify(t, Finding(finding_id="V3", check="server_version", target_path="/"))
        self.assertEqual(r.verdict, Verdict.NOT_CONFIRMED)

    def test_no_headers_not_confirmed(self):
        t = FakeTransport(default=HttpResponse(status=200))
        r = verify(t, Finding(finding_id="V4", check="server_version", target_path="/"))
        self.assertEqual(r.verdict, Verdict.NOT_CONFIRMED)


if __name__ == "__main__":
    unittest.main()
