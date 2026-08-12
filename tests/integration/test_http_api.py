"""Integration test for the REST + webhook API using the client SDK."""

import threading
import unittest

from enigma.integrations.client import EnigmaClient
from enigma.integrations.http_api import create_server
from enigma.service import EnigmaService
from enigma.verification.http import FakeTransport, HttpResponse

ASSESSMENT = {
    "assessment_id": "ASM-API",
    "target": {"url": "https://authorized-target.example/"},
    "authorization": {"status": "authorized"},
    "scope": {"allowed_hosts": ["authorized-target.example"]},
    "profile": "safe_verification",
}

FINDINGS = [
    {
        "finding_id": "F-1",
        "category": "missing_security_header",
        "target": {"path": "/search"},
        "check": "security_header",
        "parameters": {"header": "Content-Security-Policy"},
    }
]


def make_service():
    transport = FakeTransport(default=HttpResponse(status=200, headers={"Server": "x"}, body="ok"))
    return EnigmaService(transport=transport)


class HttpApiTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = create_server("127.0.0.1", 0, make_service(), token=None)
        cls.port = cls.server.server_address[1]
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()
        cls.client = EnigmaClient(f"http://127.0.0.1:{cls.port}")

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()

    def test_health(self):
        health = self.client.health()
        self.assertEqual(health["status"], "ok")
        self.assertFalse(health["auth_required"])

    def test_validate(self):
        result = self.client.validate(ASSESSMENT)
        self.assertTrue(result["allowed"])

    def test_verify_and_fetch(self):
        report = self.client.verify(ASSESSMENT, FINDINGS)
        self.assertEqual(report["results"][0]["verdict"], "CONFIRMED")
        fetched = self.client.get_result("ASM-API")
        self.assertEqual(fetched["summary"]["confirmed"], 1)

    def test_unknown_result_404(self):
        result = self.client.get_result("NOPE")
        self.assertEqual(result.get("status_code"), 404)


class HttpApiAuthTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = create_server("127.0.0.1", 0, make_service(), token="s3cr3t")
        cls.port = cls.server.server_address[1]
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()

    def test_health_needs_no_auth(self):
        client = EnigmaClient(f"http://127.0.0.1:{self.port}")
        self.assertEqual(client.health()["status"], "ok")

    def test_validate_rejects_without_token(self):
        client = EnigmaClient(f"http://127.0.0.1:{self.port}")  # no token
        result = client.validate(ASSESSMENT)
        self.assertEqual(result.get("status_code"), 401)

    def test_validate_accepts_with_token(self):
        client = EnigmaClient(f"http://127.0.0.1:{self.port}", token="s3cr3t")
        self.assertTrue(client.validate(ASSESSMENT)["allowed"])


if __name__ == "__main__":
    unittest.main()
