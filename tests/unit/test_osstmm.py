import unittest

from enigma.findings.model import Finding, Verdict
from enigma.methodologies.osstmm import OsstmmMapper


class OsstmmMapperTests(unittest.TestCase):
    def setUp(self):
        self.mapper = OsstmmMapper()

    def test_maps_security_header(self):
        finding = Finding(finding_id="F", check="security_header", target_host="h.example", target_path="/x")
        mapping = self.mapper.map(finding, Verdict.CONFIRMED)
        self.assertEqual(mapping["name"], "OSSTMM")
        self.assertEqual(mapping["channel"], "COMSEC/Data Networks")
        self.assertEqual(mapping["section"], "Configuration & Hardening")
        self.assertIn("Confidentiality", mapping["controls"])
        self.assertEqual(mapping["vector"], "h.example/x")

    def test_unknown_check_uses_default(self):
        finding = Finding(finding_id="F", check=None)
        mapping = self.mapper.map(finding, Verdict.INCONCLUSIVE)
        self.assertEqual(mapping["section"], "Information Leakage")

    def test_coverage_counts(self):
        findings = [
            Finding(finding_id="A", check="security_header"),
            Finding(finding_id="B", check="security_header"),
            Finding(finding_id="C", check="reflection"),
        ]
        coverage = self.mapper.coverage(findings)
        self.assertEqual(coverage["Configuration & Hardening"], 2)
        self.assertEqual(coverage["Integrity"], 1)


if __name__ == "__main__":
    unittest.main()
