import json
import unittest

from enigma.integrations.mcp_server import EnigmaMcpServer
from enigma.service import EnigmaService
from enigma.verification.http import FakeTransport, HttpResponse

ASSESSMENT = {
    "assessment_id": "ASM-MCP",
    "target": {"url": "https://authorized-target.example/"},
    "authorization": {"status": "authorized"},
    "scope": {"allowed_hosts": ["authorized-target.example"]},
    "profile": "safe_verification",
}

FINDING = {
    "finding_id": "F-1",
    "category": "missing_security_header",
    "target": {"path": "/search"},
    "check": "security_header",
    "parameters": {"header": "Content-Security-Policy"},
}


def server():
    transport = FakeTransport(default=HttpResponse(status=200, headers={"Server": "x"}, body="ok"))
    return EnigmaMcpServer(service=EnigmaService(transport=transport))


def call(srv, msg_id, name, arguments):
    return srv.handle_message(
        {"jsonrpc": "2.0", "id": msg_id, "method": "tools/call", "params": {"name": name, "arguments": arguments}}
    )


def tool_payload(response):
    return json.loads(response["result"]["content"][0]["text"])


class McpServerTests(unittest.TestCase):
    def test_initialize(self):
        resp = server().handle_message({"jsonrpc": "2.0", "id": 1, "method": "initialize"})
        self.assertEqual(resp["result"]["serverInfo"]["name"], "enigma")
        self.assertIn("tools", resp["result"]["capabilities"])

    def test_tools_list(self):
        resp = server().handle_message({"jsonrpc": "2.0", "id": 2, "method": "tools/list"})
        names = {t["name"] for t in resp["result"]["tools"]}
        self.assertEqual(names, {"validate_scope", "verify_findings", "get_result"})

    def test_notification_returns_none(self):
        resp = server().handle_message({"jsonrpc": "2.0", "method": "notifications/initialized"})
        self.assertIsNone(resp)

    def test_unknown_method(self):
        resp = server().handle_message({"jsonrpc": "2.0", "id": 3, "method": "does/not/exist"})
        self.assertEqual(resp["error"]["code"], -32601)

    def test_validate_scope_tool(self):
        resp = call(server(), 4, "validate_scope", {"assessment": ASSESSMENT})
        self.assertFalse(resp["result"]["isError"])
        self.assertTrue(tool_payload(resp)["allowed"])

    def test_verify_findings_tool(self):
        srv = server()
        resp = call(srv, 5, "verify_findings", {"assessment": ASSESSMENT, "findings": [FINDING]})
        payload = tool_payload(resp)
        self.assertEqual(payload["results"][0]["verdict"], "CONFIRMED")
        # result is retrievable afterwards
        got = call(srv, 6, "get_result", {"assessment_id": "ASM-MCP"})
        self.assertEqual(tool_payload(got)["summary"]["confirmed"], 1)

    def test_missing_argument_is_tool_error(self):
        resp = call(server(), 7, "verify_findings", {"findings": []})
        self.assertTrue(resp["result"]["isError"])

    def test_allowlist_violation_is_tool_error(self):
        transport = FakeTransport(default=HttpResponse(status=200))
        srv = EnigmaMcpServer(service=EnigmaService(transport=transport, allowed_hosts=["other.example"]))
        resp = call(srv, 8, "validate_scope", {"assessment": ASSESSMENT})
        self.assertTrue(resp["result"]["isError"])


if __name__ == "__main__":
    unittest.main()
