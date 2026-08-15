"""Tests for the OSSTMM RAV (Risk Assessment Value) module."""

import unittest

from enigma.findings.model import Finding, Verdict
from enigma.methodologies.osstmm.rav import (
    LIMITATION_WEIGHTS,
    RavCalculator,
    compute_rav,
)
from enigma.verification.engine import VerificationResult


def result(finding_id, check, verdict, path="/", status="completed"):
    return VerificationResult(
        assessment_id="ASM-RAV",
        finding=Finding(finding_id=finding_id, check=check, target_path=path),
        verdict=verdict,
        confidence=0.95,
        reproducible=True,
        status=status,
        procedure=check,
    )


class RavBasicsTests(unittest.TestCase):
    def test_clean_target_has_no_limitations_and_scores_high(self):
        # Everything NOT_CONFIRMED => controls evidenced, no limitations.
        # Note: OSSTMM's 100% means *perfect balance* (controls covering all
        # porosity), so a flawless-but-lightly-controlled target sits just below
        # 100 — it is not penalised for flaws, only for uncovered porosity.
        results = [
            result("A", "security_header", Verdict.NOT_CONFIRMED),
            result("B", "clickjacking", Verdict.NOT_CONFIRMED),
            result("C", "tls_redirect", Verdict.NOT_CONFIRMED),
        ]
        rav = compute_rav(results)
        self.assertEqual(rav.limitations.total, 0)
        self.assertGreater(rav.controls.total, 0)
        self.assertGreater(rav.actual_security, 90.0)
        self.assertIn(rav.grade(), {"balanced", "adequate"})

    def test_full_control_coverage_reaches_balance(self):
        """The model is internally consistent: controls_sum offsets opsec_sum
        exactly when all ten controls cover each porosity point."""

        from enigma.methodologies.osstmm.controls import Control
        from enigma.methodologies.osstmm.rav import Controls, Porosity

        porosity = Porosity(visibility=1)
        controls = Controls()
        for control in Control:  # all ten operational controls evidenced
            controls.add(control)
        self.assertAlmostEqual(controls.controls_sum, porosity.opsec_sum, places=6)

    def test_confirmed_findings_lower_actual_security(self):
        clean = compute_rav([result("A", "security_header", Verdict.NOT_CONFIRMED)])
        flawed = compute_rav([result("A", "security_header", Verdict.CONFIRMED)])
        self.assertLess(flawed.actual_security, clean.actual_security)
        self.assertEqual(flawed.limitations.total, 1)

    def test_more_confirmed_findings_lower_the_score_further(self):
        one = compute_rav([result("A", "security_header", Verdict.CONFIRMED)])
        two = compute_rav([
            result("A", "security_header", Verdict.CONFIRMED),
            result("B", "cookie_flags", Verdict.CONFIRMED, path="/a"),
        ])
        self.assertLess(two.actual_security, one.actual_security)

    def test_vulnerability_weighs_more_than_exposure(self):
        vuln = compute_rav([result("A", "cors", Verdict.CONFIRMED)])          # vulnerability
        expo = compute_rav([result("A", "server_version", Verdict.CONFIRMED)])  # exposure
        self.assertLess(vuln.actual_security, expo.actual_security)

    def test_weights_are_ordered_as_documented(self):
        self.assertGreater(LIMITATION_WEIGHTS["vulnerability"], LIMITATION_WEIGHTS["weakness"])
        self.assertGreater(LIMITATION_WEIGHTS["weakness"], LIMITATION_WEIGHTS["concern"])
        self.assertGreater(LIMITATION_WEIGHTS["concern"], LIMITATION_WEIGHTS["exposure"])
        self.assertGreater(LIMITATION_WEIGHTS["exposure"], LIMITATION_WEIGHTS["anomaly"])


class RavVerifiedOnlyTests(unittest.TestCase):
    def test_unverified_findings_are_excluded_but_counted(self):
        results = [
            result("A", "security_header", Verdict.CONFIRMED),
            result("B", None, Verdict.INCONCLUSIVE, path="/cart", status="reported"),
            result("C", None, Verdict.INCONCLUSIVE, path="/api", status="reported"),
        ]
        rav = compute_rav(results)
        self.assertEqual(rav.excluded_unverified, 2)
        # only the CONFIRMED finding became a limitation
        self.assertEqual(rav.limitations.total, 1)

    def test_ai_confidence_does_not_affect_the_score(self):
        low = result("A", "security_header", Verdict.CONFIRMED)
        low.finding.confidence = 0.01
        high = result("A", "security_header", Verdict.CONFIRMED)
        high.finding.confidence = 0.99
        self.assertEqual(compute_rav([low]).actual_security, compute_rav([high]).actual_security)

    def test_reported_only_batch_has_no_limitations(self):
        results = [result("A", None, Verdict.INCONCLUSIVE, status="reported")]
        rav = compute_rav(results)
        self.assertEqual(rav.limitations.total, 0)
        self.assertEqual(rav.excluded_unverified, 1)


class RavStructureTests(unittest.TestCase):
    def test_porosity_components_counted(self):
        results = [
            result("A", "http_method", Verdict.CONFIRMED, path="/"),      # access
            result("B", "cors", Verdict.CONFIRMED, path="/api"),          # access + trust
            result("C", "reflection", Verdict.CONFIRMED, path="/search"), # trust
        ]
        rav = compute_rav(results)
        self.assertEqual(rav.porosity.visibility, 3)  # three distinct paths
        self.assertEqual(rav.porosity.access, 2)
        self.assertEqual(rav.porosity.trust, 2)

    def test_to_dict_is_auditable(self):
        rav = compute_rav([result("A", "security_header", Verdict.CONFIRMED)])
        d = rav.to_dict()
        self.assertEqual(d["methodology"], "OSSTMM 3 RAV")
        for key in ("actual_security", "true_protection", "true_coverage", "porosity",
                    "controls", "limitations", "excluded_unverified", "basis"):
            self.assertIn(key, d)
        self.assertIn("formula", d["basis"])
        self.assertTrue(d["basis"]["verified_only"])

    def test_missing_controls_listed(self):
        rav = compute_rav([result("A", "security_header", Verdict.NOT_CONFIRMED)])
        # only Integrity evidenced -> the other nine are missing
        self.assertEqual(len(rav.controls.missing), 9)

    def test_empty_results(self):
        rav = RavCalculator().compute([])
        self.assertEqual(rav.porosity.total, 0)
        self.assertEqual(rav.limitations.total, 0)
        self.assertGreaterEqual(rav.actual_security, 100.0)

    def test_never_negative(self):
        results = [result(str(i), "cors", Verdict.CONFIRMED, path=f"/p{i}") for i in range(40)]
        self.assertGreaterEqual(compute_rav(results).actual_security, 0.0)

    def test_grades_span_the_bands(self):
        clean = compute_rav([result("A", "security_header", Verdict.NOT_CONFIRMED)])
        self.assertIn(clean.grade(), {"balanced", "adequate"})
        many = compute_rav([result(str(i), "cors", Verdict.CONFIRMED, path=f"/p{i}") for i in range(30)])
        self.assertIn(many.grade(), {"critical", "poor", "degraded"})
        self.assertLess(many.actual_security, clean.actual_security)


class RavInSummaryTests(unittest.TestCase):
    def test_summary_includes_rav(self):
        from enigma.reporting import summarize, to_markdown

        results = [
            result("A", "security_header", Verdict.CONFIRMED),
            result("B", "clickjacking", Verdict.NOT_CONFIRMED, path="/a"),
        ]
        summary = summarize(results)
        self.assertIn("actual_security", summary.rav)
        md = to_markdown(results, summary)
        self.assertIn("OSSTMM RAV", md)
        self.assertIn("Actual Security", md)


if __name__ == "__main__":
    unittest.main()
