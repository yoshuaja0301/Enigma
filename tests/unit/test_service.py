import unittest

from enigma.service import EnigmaService, ServerScopeError
from enigma.verification.http import FakeTransport, HttpResponse

ASSESSMENT = {
    "assessment_id": "ASM-SVC",
    "target": {"url": "https://authorized-target.example/"},
    "authorization": {"status": "authorized"},
    "scope": {"allowed_hosts": ["authorized-target.example"]},
    "profile": "safe_verification",
}

FINDINGS = [
    {
        "finding_id": "F-1",
        "category": "missing_security_header",
        "confidence": 0.8,
        "target": {"path": "/search"},
        "check": "security_header",
        "parameters": {"header": "Content-Security-Policy"},
    }
]


def offline_service(**kw):
    # No CSP header in default response -> the CSP finding will be CONFIRMED.
    transport = FakeTransport(default=HttpResponse(status=200, headers={"Server": "x"}, body="ok"))
    return EnigmaService(transport=transport, **kw)


class ServiceTests(unittest.TestCase):
    def test_validate_allows_authorized(self):
        result = offline_service().validate(ASSESSMENT)
        self.assertTrue(result["allowed"])
        self.assertEqual(result["assessment_id"], "ASM-SVC")

    def test_verify_returns_report(self):
        report = offline_service().verify(ASSESSMENT, FINDINGS)
        self.assertEqual(report["summary"]["total"], 1)
        self.assertEqual(report["results"][0]["verdict"], "CONFIRMED")
        self.assertEqual(report["results"][0]["methodology"]["name"], "OSSTMM")

    def test_get_result_after_verify(self):
        service = offline_service()
        service.verify(ASSESSMENT, FINDINGS)
        stored = service.get_result("ASM-SVC")
        self.assertIsNotNone(stored)
        self.assertEqual(stored["summary"]["confirmed"], 1)

    def test_server_allowlist_blocks_foreign_host(self):
        service = offline_service(allowed_hosts=["other.example"])
        self.assertTrue(service.allowlist_enabled)
        with self.assertRaises(ServerScopeError):
            service.validate(ASSESSMENT)
        with self.assertRaises(ServerScopeError):
            service.verify(ASSESSMENT, FINDINGS)

    def test_server_allowlist_permits_listed_host(self):
        service = offline_service(allowed_hosts=["authorized-target.example"])
        self.assertTrue(service.validate(ASSESSMENT)["allowed"])


if __name__ == "__main__":
    unittest.main()
