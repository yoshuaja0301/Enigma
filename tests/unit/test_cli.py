import io
import json
import unittest
from contextlib import redirect_stdout
from pathlib import Path

from enigma.cli import main

EXAMPLES = Path(__file__).resolve().parents[2] / "examples"


class CliTests(unittest.TestCase):
    def test_validate_allows_authorized_target(self):
        buf = io.StringIO()
        with redirect_stdout(buf):
            code = main(["validate", "--assessment", str(EXAMPLES / "assessment.json")])
        self.assertEqual(code, 0)
        self.assertIn("ALLOWED", buf.getvalue())

    def test_verify_offline_json(self):
        buf = io.StringIO()
        with redirect_stdout(buf):
            code = main(
                [
                    "verify",
                    "--assessment",
                    str(EXAMPLES / "assessment.json"),
                    "--findings",
                    str(EXAMPLES / "findings.json"),
                    "--format",
                    "json",
                    "--offline",
                ]
            )
        self.assertEqual(code, 0)
        payload = json.loads(buf.getvalue())
        self.assertEqual(payload["summary"]["total"], 4)

    def test_validate_blocks_unauthorized(self):
        # Craft an assessment that is out of scope by pointing at a foreign host.
        import tempfile

        data = {
            "assessment_id": "ASM-X",
            "target": {"url": "https://evil.example/"},
            "authorization": {"status": "authorized"},
            "scope": {"allowed_hosts": ["authorized-target.example"]},
            "profile": "safe_verification",
        }
        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as handle:
            json.dump(data, handle)
            path = handle.name
        buf = io.StringIO()
        with redirect_stdout(buf):
            code = main(["validate", "--assessment", path])
        self.assertEqual(code, 2)
        self.assertIn("ASSESSMENT BLOCKED", buf.getvalue())


if __name__ == "__main__":
    unittest.main()
