"""Tests for the plain-language explainer, proof rendering and live prove."""

import io
import json
import unittest
from contextlib import redirect_stdout

from enigma.cli import main
from enigma.explain import CHECK_INFO, build_proof, explain_check
from enigma.findings.normalizer import KNOWN_CHECKS
from enigma.reporting import to_html
from enigma.service import EnigmaService
from enigma.core.assessment import (
    Assessment,
    AssessmentProfile,
    Authorization,
    AuthorizationStatus,
    Scope,
)
from enigma.core.target import Target
from enigma.controller import AssessmentController
from enigma.agent.openclaw import StaticOpenClawAdapter
from enigma.verification.http import FakeTransport, HttpResponse

ASSESSMENT = {
    "assessment_id": "ASM-PROOF",
    "target": {"url": "https://authorized-target.example/"},
    "authorization": {"status": "authorized"},
    "scope": {"allowed_hosts": ["authorized-target.example"]},
    "profile": "safe_verification",
}
FINDING = {
    "finding_id": "F-1",
    "title": "CSP missing",
    "check": "security_header",
    "target": {"path": "/x"},
    "parameters": {"header": "Content-Security-Policy"},
}


def _results():
    assessment = Assessment(
        assessment_id="ASM-PROOF",
        target=Target("https://authorized-target.example/"),
        authorization=Authorization(status=AuthorizationStatus.AUTHORIZED),
        scope=Scope(allowed_hosts=["authorized-target.example"]),
        profile=AssessmentProfile.SAFE_VERIFICATION,
    )
    transport = FakeTransport(default=HttpResponse(status=200, headers={"Server": "x"}, body="hi"))
    return AssessmentController(transport=transport).run(assessment, StaticOpenClawAdapter([FINDING]))


class ExplainerTests(unittest.TestCase):
    def test_every_known_check_has_bilingual_explanation(self):
        for check in KNOWN_CHECKS:
            self.assertIn(check, CHECK_INFO, f"missing explainer for {check}")
            for lang in ("en", "id"):
                info = explain_check(check, lang)
                self.assertTrue(info["what"] and info["why"] and info["label"])

    def test_unknown_check_has_fallback(self):
        info = explain_check(None, "en")
        self.assertIn("human", info["why"].lower())


class ProofTests(unittest.TestCase):
    def test_confirmed_proof_has_receipt_and_decisive(self):
        proof = build_proof(_results()[0])
        self.assertTrue(proof["proven"])
        self.assertTrue(proof["exchanges"])                      # the receipt
        self.assertIn("Content-Security-Policy", proof["decisive"])
        self.assertEqual(proof["reproduced"]["times"], 2)
        self.assertTrue(proof["reproduced"]["consistent"])

    def test_proof_embedded_in_report_and_html(self):
        html = to_html(_results())
        self.assertIn("Proof — what we sent and got back", html)
        self.assertIn("What this means", html)

    def test_indonesian_register(self):
        proof = build_proof(_results()[0], lang="id")
        self.assertIn("browser", proof["what"].lower())


class ProveCliTests(unittest.TestCase):
    def test_prove_command_prints_plain_proof(self):
        import tempfile

        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as a:
            json.dump(ASSESSMENT, a)
            apath = a.name
        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as f:
            json.dump({"findings": [FINDING]}, f)
            fpath = f.name

        buf = io.StringIO()
        with redirect_stdout(buf):
            code = main(["prove", "--assessment", apath, "--findings", fpath, "--offline"])
        out = buf.getvalue()
        self.assertEqual(code, 0)
        self.assertIn("PROVEN", out)
        self.assertIn("What it means", out)
        self.assertIn(">>", out)  # decisive marker


class LiveProveServiceTests(unittest.TestCase):
    def _service(self):
        transport = FakeTransport(default=HttpResponse(status=200, headers={"Server": "x"}, body="hi"))
        return EnigmaService(transport=transport)

    def test_prove_reruns_single_finding(self):
        service = self._service()
        service.verify(ASSESSMENT, [FINDING])
        proved = service.prove("ASM-PROOF", "F-1")
        self.assertEqual(proved["finding_id"], "F-1")
        self.assertTrue(proved["proof"]["proven"])
        self.assertTrue(proved["proof"]["exchanges"])

    def test_prove_unknown_finding_raises(self):
        service = self._service()
        service.verify(ASSESSMENT, [FINDING])
        with self.assertRaises(KeyError):
            service.prove("ASM-PROOF", "NOPE")

    def test_prove_unknown_assessment_raises(self):
        with self.assertRaises(KeyError):
            self._service().prove("NOPE", "F-1")


if __name__ == "__main__":
    unittest.main()
