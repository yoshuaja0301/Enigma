"""Unit tests for the cookie_flags, cors and tls_redirect procedures."""

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
        assessment_id="ASM-PROC",
        target=Target("https://authorized-target.example/"),
        authorization=Authorization(status=AuthorizationStatus.AUTHORIZED),
        scope=Scope(allowed_hosts=["authorized-target.example"]),
        profile=AssessmentProfile.SAFE_VERIFICATION,
    )


def verify(transport, finding):
    return VerificationEngine(transport=transport).verify(assessment(), finding)


class CookieFlagsTests(unittest.TestCase):
    def test_missing_flag_is_confirmed(self):
        t = FakeTransport(default=HttpResponse(status=200, raw_headers=[("Set-Cookie", "sid=abc; Path=/")]))
        r = verify(t, Finding(finding_id="C1", check="cookie_flags", target_path="/", parameters={"flag": "HttpOnly"}))
        self.assertEqual(r.verdict, Verdict.CONFIRMED)
        self.assertIn("sid", r.observations[0]["cookies_missing_flag"])

    def test_present_flag_is_not_confirmed(self):
        t = FakeTransport(default=HttpResponse(status=200, raw_headers=[("Set-Cookie", "sid=abc; Path=/; HttpOnly")]))
        r = verify(t, Finding(finding_id="C2", check="cookie_flags", target_path="/", parameters={"flag": "HttpOnly"}))
        self.assertEqual(r.verdict, Verdict.NOT_CONFIRMED)

    def test_samesite_missing_confirmed(self):
        t = FakeTransport(default=HttpResponse(status=200, raw_headers=[("Set-Cookie", "sid=abc; Secure; HttpOnly")]))
        r = verify(t, Finding(finding_id="C3", check="cookie_flags", target_path="/", parameters={"flag": "SameSite"}))
        self.assertEqual(r.verdict, Verdict.CONFIRMED)

    def test_no_cookie_is_inconclusive(self):
        t = FakeTransport(default=HttpResponse(status=200))
        r = verify(t, Finding(finding_id="C4", check="cookie_flags", target_path="/", parameters={"flag": "Secure"}))
        self.assertEqual(r.verdict, Verdict.INCONCLUSIVE)
        self.assertEqual(r.status, "error")

    def test_specific_cookie_name_filter(self):
        t = FakeTransport(default=HttpResponse(status=200, raw_headers=[
            ("Set-Cookie", "tracking=1; Path=/"),          # missing HttpOnly, but not our cookie
            ("Set-Cookie", "session=xyz; Path=/; HttpOnly"),  # our cookie, has the flag
        ]))
        r = verify(t, Finding(finding_id="C5", check="cookie_flags", target_path="/",
                              parameters={"flag": "HttpOnly", "cookie": "session"}))
        self.assertEqual(r.verdict, Verdict.NOT_CONFIRMED)


class CorsTests(unittest.TestCase):
    def test_reflected_origin_is_confirmed(self):
        def handler(method, url, headers):
            return HttpResponse(status=200, headers={"Access-Control-Allow-Origin": headers.get("Origin", "")})

        r = verify(FakeTransport(handler=handler),
                   Finding(finding_id="R1", check="cors", target_path="/api"))
        self.assertEqual(r.verdict, Verdict.CONFIRMED)
        self.assertTrue(r.observations[0]["reflects_origin"])

    def test_wildcard_is_confirmed(self):
        t = FakeTransport(default=HttpResponse(status=200, headers={"Access-Control-Allow-Origin": "*"}))
        r = verify(t, Finding(finding_id="R2", check="cors", target_path="/api"))
        self.assertEqual(r.verdict, Verdict.CONFIRMED)
        self.assertTrue(r.observations[0]["wildcard"])

    def test_no_cors_header_not_confirmed(self):
        t = FakeTransport(default=HttpResponse(status=200))
        r = verify(t, Finding(finding_id="R3", check="cors", target_path="/api"))
        self.assertEqual(r.verdict, Verdict.NOT_CONFIRMED)

    def test_credentialed_reflection_flagged(self):
        def handler(method, url, headers):
            return HttpResponse(status=200, headers={
                "Access-Control-Allow-Origin": headers.get("Origin", ""),
                "Access-Control-Allow-Credentials": "true",
            })

        r = verify(FakeTransport(handler=handler), Finding(finding_id="R4", check="cors", target_path="/api"))
        self.assertEqual(r.verdict, Verdict.CONFIRMED)
        self.assertTrue(r.observations[0]["credentialed_reflection"])


class TlsRedirectTests(unittest.TestCase):
    def test_no_https_redirect_is_confirmed(self):
        t = FakeTransport(default=HttpResponse(status=200))
        r = verify(t, Finding(finding_id="T1", check="tls_redirect", target_path="/x"))
        self.assertEqual(r.verdict, Verdict.CONFIRMED)
        # the probe must have targeted the http:// variant
        self.assertTrue(all(url.startswith("http://") for _, url, _ in t.exchanges))

    def test_redirect_to_https_is_not_confirmed(self):
        t = FakeTransport(default=HttpResponse(
            status=301, headers={"Location": "https://authorized-target.example/x"}))
        r = verify(t, Finding(finding_id="T2", check="tls_redirect", target_path="/x"))
        self.assertEqual(r.verdict, Verdict.NOT_CONFIRMED)
        self.assertTrue(r.observations[0]["redirects_to_https"])

    def test_redirect_to_http_still_confirmed(self):
        t = FakeTransport(default=HttpResponse(
            status=302, headers={"Location": "http://authorized-target.example/login"}))
        r = verify(t, Finding(finding_id="T3", check="tls_redirect", target_path="/x"))
        self.assertEqual(r.verdict, Verdict.CONFIRMED)


if __name__ == "__main__":
    unittest.main()
