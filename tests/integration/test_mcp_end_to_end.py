"""End-to-end MCP test: real `enigma mcp` subprocess driven over stdio,
verifying findings against a real local HTTP target.
"""

import os
import sys
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from enigma.integrations.mcp_client import MCPStdioClient

SRC = Path(__file__).resolve().parents[2] / "src"


class _Target(BaseHTTPRequestHandler):
    def log_message(self, *args):
        return

    def do_GET(self):
        if self.path.startswith("/secure"):
            self.send_response(200)
            self.send_header("Content-Security-Policy", "default-src 'self'")
            self.end_headers()
            self.wfile.write(b"secure")
        elif self.path.startswith("/search"):
            query = self.path.split("?", 1)[1] if "?" in self.path else ""
            self.send_response(200)
            self.end_headers()
            self.wfile.write(f"echo {query}".encode())
        else:
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"hello")

    def do_OPTIONS(self):
        self.send_response(200)
        self.send_header("Allow", "GET, HEAD, OPTIONS, TRACE")
        self.end_headers()


class McpEndToEndTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = ThreadingHTTPServer(("127.0.0.1", 0), _Target)
        cls.port = cls.server.server_address[1]
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()

    def _client(self):
        env = dict(os.environ, PYTHONPATH=str(SRC))
        command = [sys.executable, "-m", "enigma", "mcp", "--allow-host", "127.0.0.1"]
        return MCPStdioClient(command, env=env)

    def _assessment(self):
        return {
            "assessment_id": "ASM-E2E",
            "target": {"url": f"http://127.0.0.1:{self.port}/"},
            "authorization": {"status": "authorized"},
            "scope": {"allowed_hosts": ["127.0.0.1"], "allowed_ports": [self.port]},
            "profile": "safe_verification",
        }

    def test_full_mcp_flow(self):
        findings = [
            {"finding_id": "F-CSP", "check": "security_header", "target": {"path": "/"},
             "parameters": {"header": "Content-Security-Policy"}},
            {"finding_id": "F-CSP2", "check": "security_header", "target": {"path": "/secure"},
             "parameters": {"header": "Content-Security-Policy"}},
            {"finding_id": "F-REF", "check": "reflection", "target": {"path": "/search"},
             "parameters": {"param": "q"}},
            {"finding_id": "F-TRACE", "check": "http_method", "target": {"path": "/"},
             "parameters": {"method": "TRACE"}},
        ]
        with self._client() as client:
            self.assertEqual(client.server_info.get("serverInfo", {}).get("name"), "enigma")
            tools = {t["name"] for t in client.list_tools()}
            self.assertEqual(tools, {"validate_scope", "verify_findings", "get_result"})

            decision = client.call_tool("validate_scope", {"assessment": self._assessment()})
            self.assertTrue(decision["allowed"])

            report = client.call_tool(
                "verify_findings", {"assessment": self._assessment(), "findings": findings}
            )
            verdicts = {r["finding_id"]: r["verdict"] for r in report["results"]}
            self.assertEqual(verdicts["F-CSP"], "CONFIRMED")
            self.assertEqual(verdicts["F-CSP2"], "NOT_CONFIRMED")
            self.assertEqual(verdicts["F-REF"], "CONFIRMED")
            self.assertEqual(verdicts["F-TRACE"], "CONFIRMED")

            fetched = client.call_tool("get_result", {"assessment_id": "ASM-E2E"})
            self.assertEqual(fetched["summary"]["confirmed"], 3)

    def test_out_of_scope_target_is_tool_error(self):
        # server allowlist is 127.0.0.1; a foreign host must be rejected.
        assessment = {
            "assessment_id": "ASM-E2E-2",
            "target": {"url": "https://not-allowed.example/"},
            "authorization": {"status": "authorized"},
            "scope": {"allowed_hosts": ["not-allowed.example"]},
            "profile": "safe_verification",
        }
        with self._client() as client:
            from enigma.integrations.mcp_client import MCPError

            with self.assertRaises(MCPError):
                client.call_tool("validate_scope", {"assessment": assessment})


if __name__ == "__main__":
    unittest.main()
