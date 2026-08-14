"""Tests for the run manifest — the integrity record attached to every report."""

import copy
import json
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
from enigma.evidence.manifest import (
    build_manifest,
    canonical_digest,
    verify_manifest,
    verify_report,
)
from enigma.reporting import to_json, to_markdown
from enigma.reporting.json import build_report
from enigma.verification.http import FakeTransport, HttpResponse

FINDINGS = [
    {
        "finding_id": "F-1",
        "source": "zap",
        "confidence": 0.85,
        "category": "security-headers",
        "target": {"path": "/"},
        "check": "security_header",
        "parameters": {"header": "Content-Security-Policy"},
    },
    {
        "finding_id": "F-2",
        "source": "nuclei",
        "confidence": 0.3,
        "category": "version-disclosure",
        "target": {"path": "/"},
        "check": "server_version",
    },
    {
        "finding_id": "F-3",
        "source": "openclaw",
        "confidence": 0.95,
        "category": "business_logic",
        "target": {"path": "/cart"},
    },
]


def build_run():
    assessment = Assessment(
        assessment_id="ASM-MAN",
        target=Target("http://target.example/"),
        authorization=Authorization(status=AuthorizationStatus.AUTHORIZED),
        scope=Scope(allowed_hosts=["target.example"]),
        profile=AssessmentProfile.SAFE_VERIFICATION,
        instruments=("nmap", "zap"),
    )
    # CSP present (so F-1 is refuted), Server leaked (so F-2 is confirmed).
    transport = FakeTransport(
        default=HttpResponse(
            status=200,
            headers={"Content-Security-Policy": "default-src 'self'", "Server": "nginx/1.18.0"},
        )
    )
    controller = AssessmentController(transport=transport)
    results = controller.run(assessment, StaticOpenClawAdapter(FINDINGS))
    return controller, assessment, results


class ManifestShapeTests(unittest.TestCase):
    def setUp(self):
        self.controller, self.assessment, self.results = build_run()
        self.manifest = self.controller.manifest(self.results, self.assessment)

    def test_records_the_run_context(self):
        data = self.manifest.to_dict()
        self.assertEqual(data["assessment_id"], "ASM-MAN")
        self.assertEqual(data["target"], "http://target.example/")
        self.assertEqual(data["profile"], "safe_verification")
        self.assertEqual(data["instruments"], ["nmap", "zap"])
        self.assertEqual(data["digest_algorithm"], "sha256")
        self.assertTrue(data["enigma_version"])
        self.assertTrue(data["python_version"])

    def test_one_entry_per_finding_in_order(self):
        ids = [entry["finding_id"] for entry in self.manifest.to_dict()["entries"]]
        self.assertEqual(ids, ["F-1", "F-2", "F-3"])
        self.assertEqual(self.manifest.to_dict()["total"], 3)

    def test_entry_carries_the_verdict_and_source(self):
        entries = {e["finding_id"]: e for e in self.manifest.to_dict()["entries"]}
        self.assertEqual(entries["F-1"]["verdict"], "NOT_CONFIRMED")
        self.assertEqual(entries["F-1"]["source"], "zap")
        self.assertEqual(entries["F-2"]["verdict"], "CONFIRMED")
        self.assertEqual(entries["F-3"]["status"], "reported")

    def test_findings_without_evidence_are_still_chained(self):
        entries = {e["finding_id"]: e for e in self.manifest.to_dict()["entries"]}
        # F-3 was only reported, so it has no evidence — but it is still linked.
        self.assertIsNone(entries["F-3"]["evidence_sha256"])
        self.assertTrue(entries["F-3"]["chain"])
        self.assertEqual(self.manifest.to_dict()["with_evidence"], 2)

    def test_chain_head_is_the_last_link(self):
        data = self.manifest.to_dict()
        self.assertEqual(data["chain_head"], data["entries"][-1]["chain"])

    def test_generated_at_can_be_pinned_for_reproducibility(self):
        stamped = "2026-01-01T00:00:00+00:00"
        first = build_manifest(self.results, self.assessment, generated_at=stamped)
        second = build_manifest(self.results, self.assessment, generated_at=stamped)
        self.assertEqual(first.chain_head, second.chain_head)

    def test_time_is_bound_into_the_chain(self):
        a = build_manifest(self.results, self.assessment, generated_at="2026-01-01T00:00:00+00:00")
        b = build_manifest(self.results, self.assessment, generated_at="2026-01-02T00:00:00+00:00")
        self.assertNotEqual(a.chain_head, b.chain_head)


class ManifestIntegrityTests(unittest.TestCase):
    def setUp(self):
        self.controller, self.assessment, self.results = build_run()
        self.manifest = self.controller.manifest(self.results, self.assessment)
        self.data = json.loads(json.dumps(self.manifest.to_dict()))

    def test_intact_manifest_reports_no_problems(self):
        self.assertEqual(verify_manifest(self.manifest), [])
        self.assertEqual(verify_manifest(self.data), [])

    def test_flipping_a_verdict_is_detected(self):
        self.data["entries"][0]["verdict"] = "CONFIRMED"
        problems = verify_manifest(self.data)
        self.assertTrue(any("F-1" in p and "digest" in p for p in problems))

    def test_only_the_first_chain_break_is_reported(self):
        self.data["entries"][0]["verdict"] = "CONFIRMED"
        breaks = [p for p in verify_manifest(self.data) if p.startswith("chain breaks")]
        self.assertEqual(len(breaks), 1)
        self.assertIn("F-1", breaks[0])

    def test_removing_an_entry_is_detected(self):
        self.data["entries"].pop(1)
        problems = verify_manifest(self.data)
        self.assertTrue(any("entr" in p for p in problems))

    def test_reordering_entries_is_detected(self):
        self.data["entries"][0], self.data["entries"][1] = (
            self.data["entries"][1],
            self.data["entries"][0],
        )
        self.assertTrue(verify_manifest(self.data))

    def test_editing_the_run_header_is_detected(self):
        self.data["target"] = "http://somewhere-else.example/"
        problems = verify_manifest(self.data)
        self.assertIn("run header does not match the recorded genesis digest", problems)

    def test_editing_chain_head_alone_is_detected(self):
        # Nothing else is touched, so no entry-level break masks this.
        self.data["chain_head"] = "0" * 64
        self.assertIn(
            "chain_head does not match the recomputed chain", verify_manifest(self.data)
        )

    def test_every_published_header_field_is_covered_by_the_chain(self):
        # A field shown to a reader but outside the digest would be forgeable.
        for key in ("with_evidence", "digest_algorithm", "summary_sha256"):
            with self.subTest(field=key):
                mutated = copy.deepcopy(self.data)
                mutated[key] = "tampered"
                self.assertTrue(verify_manifest(mutated), f"{key} is not chained")

    def test_edited_evidence_is_detected(self):
        evidence = {e.evidence_id: e.to_dict() for e in self.controller.evidence_store.all()}
        target = self.data["entries"][0]["evidence_id"]
        evidence[target]["notes"] = ["(edited after the fact)"]
        problems = verify_manifest(self.data, evidence)
        self.assertTrue(any(target in p and "digest" in p for p in problems))

    def test_missing_evidence_is_detected(self):
        problems = verify_manifest(self.data, {})
        self.assertTrue(any("referenced but missing" in p for p in problems))

    def test_unedited_evidence_passes(self):
        evidence = {e.evidence_id: e.to_dict() for e in self.controller.evidence_store.all()}
        self.assertEqual(verify_manifest(self.data, evidence), [])


class ReportIntegrityTests(unittest.TestCase):
    """The chain must cover what a reader is actually shown, not just verdicts."""

    def setUp(self):
        self.controller, self.assessment, self.results = build_run()
        self.report = json.loads(
            json.dumps(build_report(self.results, assessment=self.assessment))
        )
        self.evidence = {
            e.evidence_id: e.to_dict() for e in self.controller.evidence_store.all()
        }

    def _tampered(self, mutate):
        report = copy.deepcopy(self.report)
        mutate(report)
        return verify_report(report, self.evidence)

    def test_an_untouched_report_verifies(self):
        self.assertEqual(verify_report(self.report, self.evidence), [])

    def test_flipping_a_published_verdict_is_detected(self):
        problems = self._tampered(
            lambda r: r["results"][0].__setitem__("verdict", "CONFIRMED")
        )
        self.assertTrue(any("published record" in p for p in problems))

    def test_doctoring_the_proof_receipt_is_detected(self):
        def mutate(report):
            report["results"][0]["proof"]["exchanges"][0]["response_headers"] = {
                "Server": "fabricated/9.9"
            }

        self.assertTrue(any("published record" in p for p in self._tampered(mutate)))

    def test_rewriting_a_summary_metric_is_detected(self):
        problems = self._tampered(
            lambda r: r["summary"].__setitem__("confirmation_rate", 0.99)
        )
        self.assertIn("report summary does not match its recorded digest", problems)

    def test_rewriting_by_source_is_detected(self):
        problems = self._tampered(lambda r: r["summary"].__setitem__("by_source", {}))
        self.assertIn("report summary does not match its recorded digest", problems)

    def test_appending_a_fabricated_finding_is_detected(self):
        problems = self._tampered(
            lambda r: r["results"].append({"finding_id": "FAKE", "verdict": "CONFIRMED"})
        )
        self.assertTrue(any("result(s) but the manifest records" in p for p in problems))

    def test_a_report_without_a_manifest_is_refused(self):
        self.assertEqual(verify_report({"results": []}), ["report carries no manifest"])

    def test_a_manifest_that_binds_nothing_is_called_out(self):
        # A manifest built without the published records cannot vouch for them,
        # and must say so rather than pass silently.
        bare = build_manifest(self.results, self.assessment).to_dict()
        report = copy.deepcopy(self.report)
        report["manifest"] = bare
        problems = verify_report(report)
        self.assertIn("manifest does not bind the report summary", problems)
        self.assertTrue(any("does not bind its published record" in p for p in problems))

    def test_records_must_align_with_results(self):
        with self.assertRaises(ValueError):
            build_manifest(self.results, self.assessment, records=[{}])


class CanonicalDigestTests(unittest.TestCase):
    def test_key_order_does_not_change_the_digest(self):
        self.assertEqual(
            canonical_digest({"a": 1, "b": 2}), canonical_digest({"b": 2, "a": 1})
        )

    def test_different_values_change_the_digest(self):
        self.assertNotEqual(canonical_digest({"a": 1}), canonical_digest({"a": 2}))


class ManifestInReportsTests(unittest.TestCase):
    def setUp(self):
        self.controller, self.assessment, self.results = build_run()

    def test_json_report_carries_a_verifiable_manifest(self):
        payload = json.loads(to_json(self.results, assessment=self.assessment))
        self.assertIn("manifest", payload)
        self.assertEqual(verify_manifest(payload["manifest"]), [])
        self.assertEqual(verify_report(payload), [])

    def test_cli_style_shared_manifest_still_binds_the_report(self):
        # The CLI builds one summary + manifest and hands them to the renderer;
        # the digests must still match what the renderer publishes.
        summary = self.controller.summarize(self.results, self.assessment)
        manifest = self.controller.manifest(self.results, self.assessment, summary=summary)
        payload = json.loads(to_json(self.results, summary=summary, manifest=manifest))
        self.assertEqual(verify_report(payload), [])

    def test_json_manifest_covers_every_result(self):
        payload = json.loads(to_json(self.results, assessment=self.assessment))
        self.assertEqual(len(payload["manifest"]["entries"]), len(payload["results"]))

    def test_markdown_renders_the_chain_head(self):
        manifest = self.controller.manifest(self.results, self.assessment)
        md = to_markdown(self.results, manifest=manifest)
        self.assertIn("## Run manifest", md)
        self.assertIn(manifest.chain_head, md)

    def test_markdown_omits_the_section_without_a_manifest(self):
        self.assertNotIn("## Run manifest", to_markdown(self.results))


if __name__ == "__main__":
    unittest.main()
