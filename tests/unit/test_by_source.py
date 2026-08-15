"""Tests for per-source metrics — which finder's claims survive verification."""

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
from enigma.reporting import to_html, to_json, to_markdown
from enigma.reporting.summary import SourceStats, summarize
from enigma.verification.http import FakeTransport, HttpResponse

# The server sets CSP but leaks its Server header. So: a high-confidence ZAP
# claim about CSP is refuted, a low-confidence Nuclei claim about the version
# banner is confirmed, and OpenClaw's free-form finding stays undecided.
FINDINGS = [
    {
        "finding_id": "ZAP-1",
        "source": "zap",
        "confidence": 0.85,
        "category": "security-headers",
        "target": {"path": "/"},
        "check": "security_header",
        "parameters": {"header": "Content-Security-Policy"},
    },
    {
        "finding_id": "NUCLEI-1",
        "source": "nuclei",
        "confidence": 0.3,
        "category": "version-disclosure",
        "target": {"path": "/"},
        "check": "server_version",
    },
    {
        "finding_id": "OC-1",
        "source": "openclaw",
        "confidence": 0.95,
        "category": "business_logic",
        "target": {"path": "/cart"},
    },
    {
        "finding_id": "OC-2",
        "source": "openclaw",
        "confidence": 0.4,
        "category": "clickjacking",
        "target": {"path": "/"},
        "check": "clickjacking",
    },
]


def build_results():
    assessment = Assessment(
        assessment_id="ASM-SRC",
        target=Target("http://target.example/"),
        authorization=Authorization(status=AuthorizationStatus.AUTHORIZED),
        scope=Scope(allowed_hosts=["target.example"]),
        profile=AssessmentProfile.SAFE_VERIFICATION,
    )
    transport = FakeTransport(
        default=HttpResponse(
            status=200,
            headers={"Content-Security-Policy": "default-src 'self'", "Server": "nginx/1.18.0"},
        )
    )
    return AssessmentController(transport=transport).run(
        assessment, StaticOpenClawAdapter(FINDINGS)
    )


class SourceStatsTests(unittest.TestCase):
    def test_rates_divide_by_decided_not_total(self):
        stats = SourceStats(source="x", total=10, confirmed=3, not_confirmed=1, reported=6)
        self.assertEqual(stats.decided, 4)
        self.assertEqual(stats.undecided, 6)
        self.assertAlmostEqual(stats.confirmation_rate, 0.75)
        self.assertAlmostEqual(stats.refutation_rate, 0.25)

    def test_no_decided_findings_yields_zero_not_a_crash(self):
        stats = SourceStats(source="x", total=3, reported=3)
        self.assertEqual(stats.decided, 0)
        self.assertEqual(stats.confirmation_rate, 0.0)
        self.assertEqual(stats.refutation_rate, 0.0)

    def test_to_dict_states_its_denominator(self):
        self.assertEqual(SourceStats(source="x").to_dict()["rate_denominator"], "decided")


class SummaryBySourceTests(unittest.TestCase):
    def setUp(self):
        self.summary = summarize(build_results())

    def test_every_source_appears(self):
        self.assertEqual(set(self.summary.by_source), {"zap", "nuclei", "openclaw"})

    def test_counts_split_per_source(self):
        self.assertEqual(self.summary.by_source["openclaw"].total, 2)
        self.assertEqual(self.summary.by_source["zap"].total, 1)

    def test_per_source_totals_add_up_to_the_global_total(self):
        self.assertEqual(
            sum(s.total for s in self.summary.by_source.values()), self.summary.total
        )
        self.assertEqual(
            sum(s.confirmed for s in self.summary.by_source.values()), self.summary.confirmed
        )
        self.assertEqual(
            sum(s.not_confirmed for s in self.summary.by_source.values()),
            self.summary.not_confirmed,
        )

    def test_confident_tool_can_score_zero(self):
        # ZAP claimed CSP was missing at 0.85 confidence; the server sent one.
        zap = self.summary.by_source["zap"]
        self.assertEqual(zap.not_confirmed, 1)
        self.assertEqual(zap.confirmation_rate, 0.0)
        self.assertAlmostEqual(zap.avg_claimed_confidence, 0.85)

    def test_unconfident_tool_can_score_full(self):
        # Nuclei claimed the version banner at 0.30; the server disclosed one.
        nuclei = self.summary.by_source["nuclei"]
        self.assertEqual(nuclei.confirmed, 1)
        self.assertEqual(nuclei.confirmation_rate, 1.0)

    def test_undecided_findings_do_not_count_against_a_source(self):
        openclaw = self.summary.by_source["openclaw"]
        self.assertEqual(openclaw.total, 2)
        self.assertEqual(openclaw.reported, 1)  # the business-logic finding
        self.assertEqual(openclaw.decided, 1)
        self.assertEqual(openclaw.confirmation_rate, 1.0)

    def test_missing_source_is_labelled_unknown(self):
        results = build_results()
        results[0].finding.source = ""
        self.assertIn("unknown", summarize(results).by_source)

    def test_claimed_confidence_is_averaged_across_a_source(self):
        # OpenClaw contributed two findings, at 0.95 and 0.40.
        self.assertAlmostEqual(
            self.summary.by_source["openclaw"].avg_claimed_confidence, 0.675
        )
        # A single-finding source reports that finding's own value.
        self.assertAlmostEqual(self.summary.by_source["nuclei"].avg_claimed_confidence, 0.3)


class BlockedSourceTests(unittest.TestCase):
    """A source whose findings were all blocked has nothing to be judged on."""

    def setUp(self):
        # The target is not in the declared scope, so the gate refuses every
        # probe and nothing is sent.
        assessment = Assessment(
            assessment_id="ASM-BLOCK",
            target=Target("http://target.example/"),
            authorization=Authorization(status=AuthorizationStatus.AUTHORIZED),
            scope=Scope(allowed_hosts=["somewhere-else.example"]),
            profile=AssessmentProfile.SAFE_VERIFICATION,
        )
        blocked = dict(FINDINGS[0], finding_id="ZAP-OUT")
        self.results = AssessmentController(
            transport=FakeTransport(default=HttpResponse(status=200))
        ).run(assessment, StaticOpenClawAdapter([blocked]))
        self.summary = summarize(self.results)

    def test_the_finding_really_was_blocked(self):
        self.assertTrue(self.results[0].blocked)

    def test_a_blocked_finding_is_counted_against_its_source(self):
        zap = self.summary.by_source["zap"]
        self.assertEqual(zap.blocked, 1)
        self.assertEqual(zap.total, 1)
        self.assertEqual(zap.blocked, self.summary.blocked)

    def test_a_blocked_finding_is_undecided_not_a_failure(self):
        zap = self.summary.by_source["zap"]
        self.assertEqual(zap.decided, 0)
        self.assertEqual(zap.undecided, 1)
        self.assertEqual(zap.confirmation_rate, 0.0)

    def test_renderers_show_no_rate_rather_than_zero_percent(self):
        # A source with nothing decided must not be rendered as a 0% score.
        row = "| `zap` | 1 | 0 | 0 | 1 | n/a | 0.85 |"
        self.assertIn(row, to_markdown(self.results))
        self.assertIn(
            '<td><code>zap</code></td><td>1</td><td class="ok">0</td>'
            '<td class="bad">0</td><td>1</td><td>n/a</td><td>0.85</td>',
            to_html(self.results),
        )


class BySourceInReportsTests(unittest.TestCase):
    def setUp(self):
        self.results = build_results()

    def test_json_summary_carries_by_source(self):
        payload = json.loads(to_json(self.results))
        by_source = payload["summary"]["by_source"]
        self.assertEqual(by_source["zap"]["confirmation_rate"], 0.0)
        self.assertEqual(by_source["nuclei"]["confirmation_rate"], 1.0)

    def test_markdown_has_a_by_source_table(self):
        md = to_markdown(self.results)
        self.assertIn("## By source", md)
        self.assertIn("`zap`", md)
        self.assertIn("`nuclei`", md)

    def test_html_renders_the_actual_numbers_not_just_the_heading(self):
        html = to_html(self.results)
        self.assertIn("<h2>By source</h2>", html)
        # openclaw: 2 findings, 1 confirmed, 0 refuted, 1 undecided, 100%, 0.68
        self.assertIn(
            "<td><code>openclaw</code></td><td>2</td>"
            '<td class="ok">1</td><td class="bad">0</td>'
            "<td>1</td><td>100%</td><td>0.68</td>",
            html,
        )
        # zap: high-confidence claim the server refuted
        self.assertIn(
            '<td><code>zap</code></td><td>1</td><td class="ok">0</td>'
            '<td class="bad">1</td><td>0</td><td>0%</td><td>0.85</td>',
            html,
        )

    def test_html_rows_are_ordered_by_volume(self):
        html = to_html(self.results)
        order = [html.index(f"<code>{name}</code>") for name in ("openclaw", "nuclei", "zap")]
        self.assertEqual(order, sorted(order))

    def test_html_escapes_the_source_name(self):
        results = build_results()
        results[0].finding.source = "<script>alert(1)</script>"
        html = to_html(results)
        self.assertNotIn("<script>alert(1)</script>", html)
        self.assertIn("&lt;script&gt;", html)

    def test_markdown_omits_the_table_when_there_are_no_findings(self):
        self.assertNotIn("## By source", to_markdown([]))


if __name__ == "__main__":
    unittest.main()
