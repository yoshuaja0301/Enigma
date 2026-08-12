"""Fixture-driven tests: messy OpenClaw output must normalize safely.

These load the fixture through the same public path the CLI uses
(``StaticOpenClawAdapter.from_file``) so the file-loading path is covered too.
"""

import unittest
from pathlib import Path

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
from enigma.findings.normalizer import FindingNormalizer
from enigma.verification.http import FakeTransport, HttpResponse

FIXTURE = Path(__file__).resolve().parents[1] / "fixtures" / "openclaw_raw_findings.json"


def assessment():
    return Assessment(
        assessment_id="ASM-FIXTURE",
        target=Target("https://authorized-target.example/"),
        authorization=Authorization(status=AuthorizationStatus.AUTHORIZED),
        scope=Scope(allowed_hosts=["authorized-target.example"]),
        profile=AssessmentProfile.SAFE_VERIFICATION,
    )


class FixtureNormalizationTests(unittest.TestCase):
    def setUp(self):
        raw = StaticOpenClawAdapter.from_file(FIXTURE).get_findings(assessment())
        # The fixture's "_comment" key lives on the wrapper object, not in the
        # findings array, so every entry here is a real finding.
        self.raw = raw
        self.findings = FindingNormalizer().normalize_many(raw)

    def test_loads_all_findings(self):
        self.assertEqual(len(self.findings), 5)

    def test_every_finding_gets_an_id(self):
        ids = [f.finding_id for f in self.findings]
        self.assertTrue(all(ids), "every finding must have an id")
        self.assertEqual(len(set(ids)), len(ids), "ids must be unique")

    def test_id_alias_is_honoured(self):
        self.assertIn("OC-101", [f.finding_id for f in self.findings])

    def test_confidence_is_clamped(self):
        for f in self.findings:
            self.assertGreaterEqual(f.confidence, 0.0)
            self.assertLessEqual(f.confidence, 1.0)

    def test_checks_inferred_from_category(self):
        by_id = {f.finding_id: f for f in self.findings}
        self.assertEqual(by_id["OC-101"].check, "reflection")  # from reflected_input

    def test_unknown_category_has_no_check(self):
        by_id = {f.finding_id: f for f in self.findings}
        self.assertIsNone(by_id["OC-103"].check)

    def test_missing_path_defaults_to_root(self):
        by_id = {f.finding_id: f for f in self.findings}
        self.assertEqual(by_id["OC-104"].target_path, "/")

    def test_pipeline_handles_whole_fixture(self):
        # No security headers in the response -> header findings confirm;
        # body does not echo -> reflection does not; no Allow header -> error.
        transport = FakeTransport(default=HttpResponse(status=200, headers={"Server": "x"}, body="static"))
        results = AssessmentController(transport=transport).run(
            assessment(), StaticOpenClawAdapter.from_file(FIXTURE)
        )
        self.assertEqual(len(results), 5)
        by_id = {r.finding.finding_id: r for r in results}

        self.assertEqual(by_id["OC-100"].verdict, Verdict.CONFIRMED)      # CSP absent
        self.assertEqual(by_id["OC-104"].verdict, Verdict.CONFIRMED)      # XFO absent
        self.assertEqual(by_id["OC-101"].verdict, Verdict.NOT_CONFIRMED)  # no reflection
        # Unknown category -> no safe procedure -> kept for manual review, never
        # dropped and never probed unsafely.
        self.assertEqual(by_id["OC-103"].verdict, Verdict.INCONCLUSIVE)
        self.assertEqual(by_id["OC-103"].status, "needs_manual_review")

        # Every result carries an OSSTMM mapping.
        for result in results:
            self.assertEqual(result.methodology["name"], "OSSTMM")


if __name__ == "__main__":
    unittest.main()
