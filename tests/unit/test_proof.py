"""Tests for the plain-language explainer, proof rendering and live prove."""

import io
import json
import re
import unittest
from contextlib import redirect_stdout

from enigma.cli import main
from enigma.explain import (
    _DECISIVE,
    _UI,
    CHECK_INFO,
    _decisive,
    _decisive_key,
    build_proof,
    explain_check,
    translate_reason,
    ui_labels,
)

_FORMAT_SLOTS = re.compile(r"\{(\w+)\}")
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


class TranslationCompletenessTests(unittest.TestCase):
    """`--lang id` must not leave the important lines in English.

    The decisive statement is the whole point of a proof; a half-translated
    receipt is worse than an English one, because it reads as complete.
    """

    def test_every_decisive_statement_is_bilingual(self):
        for key, wording in _DECISIVE.items():
            for lang in ("en", "id"):
                self.assertIn(lang, wording, f"{key} has no {lang}")
                self.assertTrue(wording[lang].strip(), f"{key}/{lang} is empty")

    def test_translations_keep_every_placeholder(self):
        # A translation that drops {header} silently loses the fact's subject.
        for key, wording in _DECISIVE.items():
            slots = {f for f in _FORMAT_SLOTS.findall(wording["en"])}
            for lang in wording:
                self.assertEqual(
                    slots, {f for f in _FORMAT_SLOTS.findall(wording[lang])},
                    f"{key}/{lang} does not carry the same placeholders as en")

    def test_every_ui_label_is_bilingual(self):
        for key in _UI["en"]:
            self.assertIn(key, _UI["id"], f"Indonesian UI is missing {key!r}")
            self.assertTrue(_UI["id"][key].strip())

    def test_which_fact_is_stated_does_not_depend_on_language(self):
        # Same observation, both languages: one key, two wordings.
        obs = {"header": "Content-Security-Policy", "present": False}
        key, _ = _decisive_key("security_header", obs)
        self.assertEqual(key, "security_header.absent")
        en = _decisive("security_header", obs, "en")
        idn = _decisive("security_header", obs, "id")
        self.assertNotEqual(en, idn)
        for rendered in (en, idn):
            self.assertIn("Content-Security-Policy", rendered)

    def test_unknown_language_falls_back_to_english(self):
        obs = {"frameable": True}
        self.assertEqual(_decisive("clickjacking", obs, "fr"),
                         _decisive("clickjacking", obs, "en"))

    def test_engine_reasons_are_translated_but_unknown_text_passes_through(self):
        self.assertEqual(
            translate_reason("no automatic check for this finding type; reported for review", "id"),
            "tidak ada pemeriksaan otomatis untuk jenis temuan ini; dicatat untuk ditinjau")
        # Parameterised reasons keep their payload.
        self.assertEqual(translate_reason("all probes failed: timeout", "id"),
                         "semua probe gagal: timeout")
        self.assertEqual(translate_reason("procedure 'cors' requires additional parameters", "id"),
                         "prosedur 'cors' butuh parameter tambahan")
        # Anything unrecognised is passed through, never dropped or invented.
        self.assertEqual(translate_reason("something new from the engine", "id"),
                         "something new from the engine")
        self.assertEqual(translate_reason("no successful probes", "en"), "no successful probes")


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

    def _prove_output(self, findings, lang):
        import tempfile

        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as a:
            json.dump(ASSESSMENT, a)
            apath = a.name
        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as f:
            json.dump({"findings": findings}, f)
            fpath = f.name
        buf = io.StringIO()
        with redirect_stdout(buf):
            code = main(["prove", "--assessment", apath, "--findings", fpath,
                         "--offline", "--lang", lang])
        self.assertEqual(code, 0)
        return buf.getvalue()

    def test_indonesian_output_leaks_no_english_labels(self):
        out = self._prove_output([FINDING], "id")
        for english in ("What it means", "Why it matters", "How we checked",
                        "OBSERVED (fact)", "Limits of this verdict", "PROVEN",
                        "Repeated", "same result each time"):
            self.assertNotIn(english, out, f"English leaked into --lang id: {english!r}")
        for indonesian in ("Artinya", "Kenapa penting", "DIAMATI (fakta)",
                           "Batas dari putusan ini", "Diulang"):
            self.assertIn(indonesian, out)

    def test_indonesian_decisive_line_is_indonesian(self):
        out = self._prove_output([FINDING], "id")
        decisive = [ln for ln in out.splitlines() if "DIAMATI" in ln][0]
        self.assertIn("Jawaban server", decisive)
        self.assertIn("Content-Security-Policy", decisive)   # the fact survives

    def test_unprobed_finding_does_not_claim_results_varied(self):
        # 0 probes is neither consistent nor varied; saying either is a lie.
        unknown = {"finding_id": "F-2", "title": "business logic",
                   "category": "business_logic", "target": {"path": "/x"}}
        for lang, expected in (("en", "Not probed"), ("id", "Tidak diprobe")):
            out = self._prove_output([unknown], lang)
            self.assertIn(expected, out)
            self.assertNotIn("results varied", out)
            self.assertNotIn("hasilnya berbeda-beda", out)


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


class LimitsTests(unittest.TestCase):
    """Every verdict must state what it does NOT establish."""

    def test_confirmed_states_it_does_not_prove_exploitability(self):
        proof = build_proof(_results()[0])
        joined = " ".join(proof["limits"]).lower()
        self.assertTrue(proof["limits"])
        self.assertIn("does not establish exploitability", joined)
        # observation (fact) is kept separate from conclusion (claim)
        self.assertTrue(proof["observation"])
        self.assertEqual(proof["observation"], proof["decisive"])

    def test_not_confirmed_does_not_claim_safety(self):
        from enigma.explain import verdict_limits

        joined = " ".join(verdict_limits("NOT_CONFIRMED")).lower()
        self.assertIn("does not mean the target is safe", joined)

    def test_reported_is_flagged_as_not_evidence(self):
        from enigma.explain import verdict_limits

        limits = verdict_limits("INCONCLUSIVE", status="reported")
        self.assertIn("not evidence", " ".join(limits).lower())

    def test_limits_available_in_indonesian(self):
        from enigma.explain import verdict_limits

        joined = " ".join(verdict_limits("NOT_CONFIRMED", lang="id")).lower()
        self.assertIn("bukan berarti target aman", joined)

    def test_limits_rendered_in_html(self):
        html = to_html(_results())
        self.assertIn("does and does not establish", html)


if __name__ == "__main__":
    unittest.main()
