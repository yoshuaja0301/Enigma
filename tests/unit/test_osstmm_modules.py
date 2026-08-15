"""Tests for the OSSTMM phase/module taxonomy, instrument mapping and coverage."""

import unittest

from enigma.core.configuration import load_assessment
from enigma.findings.normalizer import KNOWN_CHECKS
from enigma.methodologies.osstmm.modules import (
    CHECK_MODULE_MAP,
    INSTRUMENTS,
    MODULES,
    Phase,
    compute_module_coverage,
    modules_in_phase,
    resolve_instrument,
)


class TaxonomyTests(unittest.TestCase):
    def test_seventeen_modules_across_four_phases(self):
        self.assertEqual(len(MODULES), 17)
        self.assertEqual(sorted(MODULES), list(range(1, 18)))
        counts = {p: len(modules_in_phase(p)) for p in Phase}
        # OSSTMM 3: A=3, B=4, C=6, D=4
        self.assertEqual(counts[Phase.A], 3)
        self.assertEqual(counts[Phase.B], 4)
        self.assertEqual(counts[Phase.C], 6)
        self.assertEqual(counts[Phase.D], 4)

    def test_module_numbers_are_unique_and_named(self):
        for number, module in MODULES.items():
            self.assertEqual(module.number, number)
            self.assertTrue(module.name)


class InstrumentTests(unittest.TestCase):
    def test_documented_tool_mapping(self):
        # Mirrors the methodology: Nmap -> B, WhatWeb/Nuclei -> C, ZAP -> B and C.
        self.assertEqual(INSTRUMENTS["nmap"].modules, (4, 5))
        self.assertEqual(INSTRUMENTS["nmap"].phases, [Phase.B])

        self.assertEqual(INSTRUMENTS["whatweb"].modules, (9, 12))
        self.assertEqual(INSTRUMENTS["whatweb"].phases, [Phase.C])

        self.assertEqual(INSTRUMENTS["nuclei"].modules, (12,))
        self.assertEqual(INSTRUMENTS["nuclei"].phases, [Phase.C])

        self.assertEqual(INSTRUMENTS["zap"].modules, (7, 12))
        self.assertEqual(INSTRUMENTS["zap"].phases, [Phase.B, Phase.C])

    def test_enigma_covers_posture_review(self):
        # The authorization-first gate is the posture review (module 1).
        self.assertIn(1, INSTRUMENTS["enigma"].modules)

    def test_alias_resolution(self):
        self.assertEqual(resolve_instrument("OWASP ZAP").key, "zap")
        self.assertEqual(resolve_instrument("  Nmap ").key, "nmap")
        self.assertIsNone(resolve_instrument("burp"))

    def test_every_known_check_maps_to_real_modules(self):
        for check in KNOWN_CHECKS:
            self.assertIn(check, CHECK_MODULE_MAP, f"no module mapping for {check}")
            for number in CHECK_MODULE_MAP[check]:
                self.assertIn(number, MODULES)


class CoverageTests(unittest.TestCase):
    def test_full_instrument_set_covers_a_b_c_but_not_d(self):
        report = compute_module_coverage(
            instruments=["nmap", "whatweb", "nuclei", "zap", "enigma"],
            checks=list(KNOWN_CHECKS),
        )
        by_phase = {p.phase: p for p in report.phases}
        covered = {mc.module.number for p in report.phases for mc in p.modules if mc.covered}

        # Phase A: only the posture review (1) — logistics and active detection
        # verification are not exercised by this instrument set.
        self.assertEqual(covered & {1, 2, 3}, {1})
        # Phase B: fully covered (visibility, access, trust, controls).
        self.assertEqual(by_phase[Phase.B].covered, by_phase[Phase.B].total)
        # Phase C: configuration (9), segregation (11) and exposure (12).
        # Process verification (8), property validation (10) and competitive
        # intelligence scouting (13) are not reachable this way.
        self.assertEqual(covered & {8, 9, 10, 11, 12, 13}, {9, 11, 12})
        # Phase D needs intrusive/internal testing — honestly reported as uncovered.
        self.assertEqual(by_phase[Phase.D].covered, 0)

    def test_attribution_records_what_covered_a_module(self):
        report = compute_module_coverage(instruments=["nmap"], checks=["cors"])
        by_number = {mc.module.number: mc for p in report.phases for mc in p.modules}
        self.assertIn("Nmap", by_number[4].covered_by)          # visibility audit
        self.assertIn("Enigma:cors", by_number[6].covered_by)   # trust verification

    def test_unknown_instrument_is_reported_not_silently_dropped(self):
        report = compute_module_coverage(instruments=["nmap", "burp"])
        self.assertEqual(report.unknown_instruments, ["burp"])
        self.assertEqual(report.instruments, ["nmap"])

    def test_empty_coverage(self):
        report = compute_module_coverage()
        self.assertEqual(report.covered, 0)
        self.assertEqual(report.total, 17)
        self.assertEqual(len(report.missing()), 17)

    def test_missing_lists_uncovered_modules(self):
        report = compute_module_coverage(instruments=["nmap"])
        missing = {m.number for m in report.missing()}
        self.assertNotIn(4, missing)
        self.assertIn(17, missing)

    def test_to_dict_shape(self):
        data = compute_module_coverage(instruments=["zap"], checks=["reflection"]).to_dict()
        self.assertEqual(data["total_modules"], 17)
        self.assertIn("phases", data)
        self.assertEqual(len(data["phases"]), 4)
        self.assertIn("missing", data)


class AssessmentInstrumentsTests(unittest.TestCase):
    def test_instruments_load_from_config(self):
        assessment = load_assessment(
            {
                "assessment_id": "ASM-INSTR",
                "target": {"url": "https://a.example/"},
                "authorization": {"status": "authorized"},
                "scope": {"allowed_hosts": ["a.example"]},
                "instruments": ["nmap", "whatweb"],
            }
        )
        self.assertEqual(assessment.instruments, ("nmap", "whatweb"))
        self.assertEqual(assessment.to_dict()["instruments"], ["nmap", "whatweb"])

    def test_instruments_default_empty(self):
        assessment = load_assessment(
            {
                "assessment_id": "ASM-NONE",
                "target": {"url": "https://a.example/"},
                "authorization": {"status": "authorized"},
                "scope": {"allowed_hosts": ["a.example"]},
            }
        )
        self.assertEqual(assessment.instruments, ())


if __name__ == "__main__":
    unittest.main()
