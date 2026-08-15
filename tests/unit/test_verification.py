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


def assessment(status=AuthorizationStatus.AUTHORIZED, hosts=("authorized-target.example",)):
    return Assessment(
        assessment_id="ASM-TEST",
        target=Target("https://authorized-target.example/"),
        authorization=Authorization(status=status),
        scope=Scope(allowed_hosts=list(hosts)),
        profile=AssessmentProfile.SAFE_VERIFICATION,
    )


class VerificationEngineTests(unittest.TestCase):
    def test_confirmed_missing_header(self):
        transport = FakeTransport(default=HttpResponse(status=200, headers={"Server": "x"}, body=""))
        engine = VerificationEngine(transport=transport)
        finding = Finding(
            finding_id="F-1",
            check="security_header",
            target_path="/search",
            parameters={"header": "Content-Security-Policy"},
            confidence=0.76,
        )
        result = engine.verify(assessment(), finding)
        self.assertEqual(result.verdict, Verdict.CONFIRMED)
        self.assertTrue(result.reproducible)
        self.assertGreater(result.confidence, 0.8)
        self.assertIsNotNone(result.evidence)

    def test_not_confirmed_when_header_present(self):
        transport = FakeTransport(
            default=HttpResponse(status=200, headers={"Content-Security-Policy": "default-src 'self'"}, body="")
        )
        engine = VerificationEngine(transport=transport)
        finding = Finding(
            finding_id="F-2",
            check="security_header",
            target_path="/search",
            parameters={"header": "Content-Security-Policy"},
        )
        result = engine.verify(assessment(), finding)
        self.assertEqual(result.verdict, Verdict.NOT_CONFIRMED)

    def test_reflection_confirmed(self):
        def handler(method, url, headers):
            # echo the query marker back into the body
            marker = url.split("q=")[-1]
            return HttpResponse(status=200, body=f"results for {marker}")

        engine = VerificationEngine(transport=FakeTransport(handler=handler))
        finding = Finding(finding_id="F-3", check="reflection", target_path="/search", parameters={"param": "q"})
        result = engine.verify(assessment(), finding)
        self.assertEqual(result.verdict, Verdict.CONFIRMED)

    def test_reflection_not_confirmed(self):
        engine = VerificationEngine(transport=FakeTransport(default=HttpResponse(status=200, body="static page")))
        finding = Finding(finding_id="F-4", check="reflection", target_path="/search", parameters={"param": "q"})
        result = engine.verify(assessment(), finding)
        self.assertEqual(result.verdict, Verdict.NOT_CONFIRMED)

    def test_http_method_confirmed(self):
        transport = FakeTransport(default=HttpResponse(status=200, headers={"Allow": "GET, POST, TRACE"}))
        engine = VerificationEngine(transport=transport)
        finding = Finding(finding_id="F-5", check="http_method", target_path="/", parameters={"method": "TRACE"})
        result = engine.verify(assessment(), finding)
        self.assertEqual(result.verdict, Verdict.CONFIRMED)

    def test_http_method_not_confirmed(self):
        transport = FakeTransport(default=HttpResponse(status=200, headers={"Allow": "GET, HEAD"}))
        engine = VerificationEngine(transport=transport)
        finding = Finding(finding_id="F-6", check="http_method", target_path="/", parameters={"method": "TRACE"})
        result = engine.verify(assessment(), finding)
        self.assertEqual(result.verdict, Verdict.NOT_CONFIRMED)

    def test_blocked_when_unauthorized_sends_nothing(self):
        transport = FakeTransport(default=HttpResponse(status=200))
        engine = VerificationEngine(transport=transport)
        finding = Finding(
            finding_id="F-7",
            check="security_header",
            target_path="/x",
            parameters={"header": "X-Frame-Options"},
        )
        result = engine.verify(assessment(status=AuthorizationStatus.UNKNOWN), finding)
        self.assertTrue(result.blocked)
        self.assertEqual(result.status, "blocked")
        self.assertEqual(result.verdict, Verdict.INCONCLUSIVE)
        self.assertEqual(transport.exchanges, [])  # no probe sent

    def test_out_of_scope_is_blocked(self):
        transport = FakeTransport(default=HttpResponse(status=200))
        engine = VerificationEngine(transport=transport)
        finding = Finding(
            finding_id="F-8",
            check="security_header",
            target_path="/x",
            parameters={"header": "X-Frame-Options"},
        )
        result = engine.verify(assessment(hosts=("other.example",)), finding)
        self.assertTrue(result.blocked)
        self.assertEqual(transport.exchanges, [])

    def test_no_procedure_is_reported_not_dropped(self):
        engine = VerificationEngine(transport=FakeTransport())
        finding = Finding(finding_id="F-9", check=None, target_path="/cart")
        result = engine.verify(assessment(), finding)
        # A free-form finding with no automatic check is NOT dropped — it is
        # recorded as "reported" for a human to review.
        self.assertEqual(result.status, "reported")
        self.assertEqual(result.verdict, Verdict.INCONCLUSIVE)

    def test_network_error_is_inconclusive(self):
        transport = FakeTransport(default=HttpResponse(status=0, error="connection refused"))
        engine = VerificationEngine(transport=transport)
        finding = Finding(
            finding_id="F-10",
            check="security_header",
            target_path="/x",
            parameters={"header": "X-Frame-Options"},
        )
        result = engine.verify(assessment(), finding)
        self.assertEqual(result.verdict, Verdict.INCONCLUSIVE)
        self.assertEqual(result.status, "error")


if __name__ == "__main__":
    unittest.main()
