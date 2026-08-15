"""The rendered reports must be wholly in the language they claim.

A half-translated report is worse than an English one: it reads as finished, so
nobody goes looking for the parts that were left behind.
"""

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
from enigma.explain import _REPORT, report_labels
from enigma.reporting import to_html, to_markdown
from enigma.reporting.html import render_dashboard_html
from enigma.verification.http import FakeTransport, HttpResponse

# English chrome that must not survive into an Indonesian report. OSSTMM terms
# of art (channel/control/module names, RAV grades) are deliberately excluded —
# they are kept in English on purpose, see explain._REPORT.
ENGLISH_CHROME = [
    "Summary", "Findings", "Not confirmed", "Inconclusive", "Reproducible",
    "Confirmation rate", "False-positive rate", "By source", "Undecided",
    "What this means", "Why it matters", "Proof — what we sent and got back",
    "Run manifest", "Generated at", "Chain head", "Modules covered",
    "Probes run", "AI confidence", "Enigma confidence", "Prove it live",
    "Findings recorded", "Controls evidenced", "Actual Security",
]


def _assessment():
    return Assessment(
        assessment_id="ASM-I18N",
        target=Target("https://authorized-target.example/"),
        authorization=Authorization(status=AuthorizationStatus.AUTHORIZED),
        scope=Scope(allowed_hosts=["authorized-target.example"]),
        profile=AssessmentProfile.SAFE_VERIFICATION,
    )


def _manifest(results):
    """A real manifest, so the manifest section is actually exercised."""
    controller = AssessmentController()
    assessment = _assessment()
    summary = controller.summarize(results, assessment)
    return controller.manifest(results, assessment, summary=summary)


def _results():
    assessment = _assessment()
    findings = [
        {"finding_id": "F-1", "title": "CSP missing", "check": "security_header",
         "target": {"path": "/x"}, "parameters": {"header": "Content-Security-Policy"}},
        # No automatic check — exercises the reason path and the 0-probe line.
        {"finding_id": "F-2", "title": "business logic", "category": "business_logic",
         "target": {"path": "/y"}},
    ]
    transport = FakeTransport(default=HttpResponse(status=200, headers={"Server": "x"}, body="hi"))
    return AssessmentController(transport=transport).run(
        assessment, StaticOpenClawAdapter(findings))


class LabelTableTests(unittest.TestCase):
    def test_indonesian_covers_every_english_key(self):
        missing = set(_REPORT["en"]) - set(_REPORT["id"])
        self.assertEqual(missing, set(), f"Indonesian report labels missing: {sorted(missing)}")

    def test_no_label_is_empty(self):
        for lang, table in _REPORT.items():
            for key, value in table.items():
                self.assertTrue(str(value).strip(), f"{lang}/{key} is empty")

    def test_unknown_language_falls_back_to_english(self):
        self.assertEqual(report_labels("fr"), report_labels("en"))


class MarkdownLanguageTests(unittest.TestCase):
    def test_indonesian_markdown_has_no_english_chrome(self):
        results = _results()
        md = to_markdown(results, manifest=_manifest(results), lang="id")
        self.assertIn("Manifest run", md)          # the section really rendered
        for english in ENGLISH_CHROME:
            self.assertNotIn(english, md, f"English leaked into --lang id: {english!r}")

    def test_indonesian_markdown_is_actually_indonesian(self):
        md = to_markdown(_results(), lang="id")
        for indonesian in ("Laporan Asesmen Enigma", "## Ringkasan", "Temuan diasesmen",
                           "Tingkat pembuktian", "Putusan", "Dapat diulang"):
            self.assertIn(indonesian, md)

    def test_verdict_names_stay_verbatim_in_both_languages(self):
        # CONFIRMED/NOT_CONFIRMED are the API's vocabulary, not prose; a report
        # whose verdict names were translated could not be diffed against JSON.
        for lang in ("en", "id"):
            md = to_markdown(_results(), lang=lang)
            self.assertIn("CONFIRMED", md)

    def test_english_is_unchanged_by_default(self):
        md = to_markdown(_results())
        self.assertIn("# Enigma Assessment Report", md)
        self.assertIn("## Summary", md)


class HtmlLanguageTests(unittest.TestCase):
    def test_indonesian_html_has_no_english_chrome(self):
        html = to_html(_results(), lang="id")
        for english in ENGLISH_CHROME:
            self.assertNotIn(english, html, f"English leaked into lang=id: {english!r}")

    def test_html_declares_the_language_it_renders(self):
        self.assertIn('<html lang="id"', to_html(_results(), lang="id"))
        self.assertIn('<html lang="en"', to_html(_results()))

    def test_no_unrendered_template_expressions_leak_to_the_page(self):
        # A broken f-string prints its own source; the eye catches it, a
        # "contains Indonesian" assertion does not.
        for lang in ("en", "id"):
            html = to_html(_results(), lang=lang)
            for marker in ("{escape(", "{t[", "{proof[", "{self."):
                self.assertNotIn(marker, html, f"unrendered template in lang={lang}")

    def test_stored_english_proof_is_restated_not_left_behind(self):
        # The served page renders a stored report whose proof text is English.
        # Chrome in Indonesian around an English receipt is the failure mode
        # this whole change exists to avoid.
        html = to_html(_results(), lang="id")
        self.assertIn("Kami hanya mengirim permintaan", html)      # proof["how"]
        self.assertIn("Jawaban server", html)                      # the decisive line
        self.assertNotIn("We only sent the request", html)
        self.assertNotIn("The reply did NOT include", html)

    def test_engine_reason_on_the_card_is_translated(self):
        html = to_html(_results(), lang="id")
        self.assertNotIn("no automatic check for this finding type", html)
        self.assertIn("tidak ada pemeriksaan otomatis", html)

    def test_indonesian_html_translates_the_proof_receipt(self):
        html = to_html(_results(), lang="id")
        for indonesian in ("Artinya", "Kenapa penting", "Bukti — yang kami kirim",
                           "Keyakinan AI", "Ringkasan"):
            self.assertIn(indonesian, html)

    def test_dashboard_is_translated(self):
        page = render_dashboard_html([], lang="id")
        self.assertIn("Dasbor asesmen", page)
        self.assertNotIn("Assessment dashboard", page)

    def test_prove_button_runtime_speaks_the_page_language(self):
        from enigma.reporting.html import render_report_html
        from enigma.reporting.json import build_report

        html = render_report_html(build_report(_results()), interactive=True, lang="id")
        self.assertIn("Buktikan langsung", html)
        self.assertIn("Cek ulang langsung barusan:", html)     # injected into the JS
        self.assertNotIn("Live re-check just now", html)


if __name__ == "__main__":
    unittest.main()
