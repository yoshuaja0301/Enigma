import unittest

from enigma.findings.normalizer import FindingNormalizer


class NormalizerTests(unittest.TestCase):
    def setUp(self):
        self.n = FindingNormalizer()

    def test_maps_core_fields(self):
        finding = self.n.normalize(
            {
                "finding_id": "F-1",
                "category": "missing_security_header",
                "confidence": 0.76,
                "target": {"host": "h.example", "path": "/x"},
                "check": "security_header",
                "parameters": {"header": "Content-Security-Policy"},
            }
        )
        self.assertEqual(finding.finding_id, "F-1")
        self.assertEqual(finding.target_host, "h.example")
        self.assertEqual(finding.target_path, "/x")
        self.assertEqual(finding.check, "security_header")
        self.assertEqual(finding.parameters["header"], "Content-Security-Policy")

    def test_infers_check_from_category(self):
        finding = self.n.normalize({"category": "reflected_input"})
        self.assertEqual(finding.check, "reflection")

    def test_unknown_check_becomes_none(self):
        finding = self.n.normalize({"category": "business_logic"})
        self.assertIsNone(finding.check)

    def test_clamps_confidence(self):
        self.assertEqual(self.n.normalize({"confidence": 5}).confidence, 1.0)
        self.assertEqual(self.n.normalize({"confidence": -1}).confidence, 0.0)

    def test_generates_id_when_missing(self):
        finding = self.n.normalize({"category": "web_application"})
        self.assertTrue(finding.finding_id.startswith("F-"))

    def test_defaults_path_to_root(self):
        finding = self.n.normalize({"category": "web_application"})
        self.assertEqual(finding.target_path, "/")


if __name__ == "__main__":
    unittest.main()
