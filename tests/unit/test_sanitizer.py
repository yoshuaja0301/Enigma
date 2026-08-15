import unittest

from enigma.evidence.sanitizer import REDACTION, EvidenceSanitizer


class SanitizerTests(unittest.TestCase):
    def setUp(self):
        self.s = EvidenceSanitizer()

    def test_redacts_sensitive_headers(self):
        headers = {"Authorization": "Bearer abc.def.ghi", "Cookie": "sid=1", "X-Ok": "value"}
        clean = self.s.sanitize_headers(headers)
        self.assertEqual(clean["Authorization"], REDACTION)
        self.assertEqual(clean["Cookie"], REDACTION)
        self.assertEqual(clean["X-Ok"], "value")

    def test_redacts_bearer_in_text(self):
        out = self.s.sanitize_text("token is Bearer aZ0._-secretvalue here")
        self.assertNotIn("secretvalue", out)
        self.assertIn(REDACTION, out)

    def test_redacts_jwt(self):
        jwt = "eyJhbGc.eyJzdWIiOiIxIn0.sig-value"
        out = self.s.sanitize_text(f"jwt={jwt}")
        self.assertNotIn("sig-value", out)

    def test_redacts_password_param_keeps_name(self):
        out = self.s.sanitize_text("user=alice&password=hunter2&next=/x")
        self.assertIn("password=" + REDACTION, out)
        self.assertNotIn("hunter2", out)
        self.assertIn("user=alice", out)

    def test_redacts_email(self):
        out = self.s.sanitize_text("contact alice@example.com now")
        self.assertNotIn("alice@example.com", out)

    def test_sanitize_nested_structure(self):
        data = {"request": {"headers": {"Authorization": "Bearer x.y.z"}}, "note": "ok"}
        clean = self.s.sanitize(data)
        self.assertEqual(clean["request"]["headers"]["Authorization"], REDACTION)
        self.assertEqual(clean["note"], "ok")


if __name__ == "__main__":
    unittest.main()
