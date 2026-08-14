"""The live demo is documentation that runs, so CI has to keep it honest.

Asserts the four claims `examples/live-demo/README.md` makes, against a real
local target: verdicts come from the reply and not the claimed confidence,
per-source metrics reconcile, the manifest catches forgery, and a live re-check
flips when the target is fixed.
"""

import importlib.util
import io
import json
import unittest
from contextlib import redirect_stdout
from pathlib import Path

from enigma.evidence import verify_report

DEMO = Path(__file__).resolve().parents[2] / "examples" / "live-demo" / "five_finders_demo.py"


def load_demo():
    spec = importlib.util.spec_from_file_location("five_finders_demo", DEMO)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class LiveDemoTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.demo = load_demo()
        buf = io.StringIO()
        with redirect_stdout(buf):
            cls.report = cls.demo.main()
        cls.output = buf.getvalue()
        cls.by_id = {r["finding_id"]: r for r in cls.report["results"]}

    def test_all_five_finders_are_represented(self):
        sources = {r["finding"]["source"] for r in self.report["results"]}
        self.assertEqual(sources, {"openclaw", "nuclei", "zap", "nmap", "whatweb"})

    def test_the_most_confident_claim_is_not_adjudicated(self):
        # OpenClaw's business-logic finding: 0.93 claimed, no safe automatic check.
        oc2 = self.by_id["OC-002"]
        self.assertEqual(oc2["finding"]["ai_confidence"], 0.93)
        self.assertEqual(oc2["verdict"], "INCONCLUSIVE")
        self.assertEqual(oc2["verification"]["status"], "reported")

    def test_the_least_confident_claim_is_proven(self):
        nuclei = self.by_id["NUCLEI-0001"]
        self.assertEqual(nuclei["finding"]["ai_confidence"], 0.3)
        self.assertEqual(nuclei["verdict"], "CONFIRMED")

    def test_a_high_confidence_scanner_alert_is_refuted(self):
        # ZAP is High-confidence that /secure lacks CSP; the server sends it.
        zap = self.by_id["ZAP-0001"]
        self.assertGreaterEqual(zap["finding"]["ai_confidence"], 0.8)
        self.assertEqual(zap["verdict"], "NOT_CONFIRMED")
        self.assertIn("DID include", zap["proof"]["observation"])

    def test_per_source_counts_reconcile_with_the_totals(self):
        by_source = self.report["summary"]["by_source"]
        self.assertEqual(
            sum(s["total"] for s in by_source.values()), self.report["summary"]["total"]
        )
        self.assertEqual(
            sum(s["confirmed"] for s in by_source.values()),
            self.report["summary"]["confirmed"],
        )

    def test_the_report_verifies_against_its_own_manifest(self):
        self.assertEqual(verify_report(self.report), [])

    def test_forging_a_verdict_or_a_metric_is_caught(self):
        forged = json.loads(json.dumps(self.report))
        victim = next(
            i for i, r in enumerate(forged["results"]) if r["verdict"] == "NOT_CONFIRMED"
        )
        forged["results"][victim]["verdict"] = "CONFIRMED"
        self.assertTrue(any("published record" in p for p in verify_report(forged)))

        forged2 = json.loads(json.dumps(self.report))
        forged2["summary"]["confirmation_rate"] = 0.99
        self.assertIn(
            "report summary does not match its recorded digest", verify_report(forged2)
        )

    def test_the_live_recheck_flips_when_the_target_is_fixed(self):
        self.assertIn("▶ Prove it live (now)    : CONFIRMED", self.output)
        self.assertIn("▶ Prove it live (again)  : NOT_CONFIRMED", self.output)

    def test_the_stored_record_survives_the_live_recheck(self):
        self.assertEqual(self.by_id["OC-001"]["verdict"], "CONFIRMED")
        self.assertIn("stored record is unchanged: CONFIRMED", self.output)

    def test_the_session_cookie_never_reaches_the_report(self):
        self.assertNotIn("s3cr3t", json.dumps(self.report))


if __name__ == "__main__":
    unittest.main()
