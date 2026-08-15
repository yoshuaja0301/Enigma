import unittest

from enigma.verification.reproducibility import ReproducibilityEngine


class ReproducibilityTests(unittest.TestCase):
    def setUp(self):
        self.engine = ReproducibilityEngine()

    def test_all_true_is_reproducible(self):
        report = self.engine.assess([True, True, True])
        self.assertTrue(report.reproducible)
        self.assertTrue(report.consistent)
        self.assertEqual(report.ratio, 1.0)

    def test_all_false_is_consistent(self):
        report = self.engine.assess([False, False])
        self.assertTrue(report.consistent)
        self.assertEqual(report.ratio, 0.0)

    def test_mixed_not_reproducible(self):
        report = self.engine.assess([True, False, True])
        self.assertFalse(report.reproducible)
        self.assertFalse(report.consistent)

    def test_empty(self):
        report = self.engine.assess([])
        self.assertFalse(report.reproducible)
        self.assertEqual(report.runs, 0)


if __name__ == "__main__":
    unittest.main()
