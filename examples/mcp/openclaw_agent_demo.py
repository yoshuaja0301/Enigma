#!/usr/bin/env python3
"""End-to-end MCP integration demo.

A *simulated* OpenClaw agent connects to Enigma over the Model Context Protocol
and asks Enigma to verify its potential findings — against a real, local,
authorized target. This exercises the whole chain:

    OpenClaw (this script)
        --stdio JSON-RPC-->  `enigma mcp`  -->  EnigmaService
                                                    --HTTP-->  local target

Run it:

    python examples/mcp/openclaw_agent_demo.py

No installation and no external network required: the target is a throwaway
server on 127.0.0.1, and Enigma is launched straight from ``src/``.
"""

from __future__ import annotations

import os
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

# Make `enigma` importable from the repo's src/ without installation.
SRC = Path(__file__).resolve().parents[2] / "src"
sys.path.insert(0, str(SRC))

from enigma.integrations.mcp_client import MCPStdioClient  # noqa: E402


# --------------------------------------------------------------------------- #
# A tiny local "target" with a few intentionally observable traits.
# --------------------------------------------------------------------------- #
class _Target(BaseHTTPRequestHandler):
    def log_message(self, *args):
        return

    def do_GET(self):
        if self.path.startswith("/secure"):
            # This path DOES set CSP -> a "missing CSP" guess here is a false positive.
            self.send_response(200)
            self.send_header("Content-Security-Policy", "default-src 'self'")
            self.end_headers()
            self.wfile.write(b"secure page")
        elif self.path.startswith("/search"):
            query = self.path.split("?", 1)[1] if "?" in self.path else ""
            self.send_response(200)
            self.end_headers()
            self.wfile.write(f"results for {query}".encode())  # reflects input
        else:
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"hello")  # no CSP header

    def do_OPTIONS(self):
        self.send_response(200)
        self.send_header("Allow", "GET, HEAD, OPTIONS, TRACE")  # advertises TRACE
        self.end_headers()


def _start_target():
    server = ThreadingHTTPServer(("127.0.0.1", 0), _Target)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server, server.server_address[1]


def main() -> int:
    target, port = _start_target()
    base = f"http://127.0.0.1:{port}"

    # The assessment the operator authorizes (target-agnostic config).
    assessment = {
        "assessment_id": "ASM-MCP-DEMO",
        "target": {"url": base + "/"},
        "authorization": {"status": "authorized", "reference": "DEMO-ROE"},
        "scope": {"allowed_hosts": ["127.0.0.1"], "allowed_ports": [port]},
        "profile": "safe_verification",
    }

    # The *potential* findings OpenClaw proposes (its hypotheses + confidence).
    findings = [
        {
            "finding_id": "OC-1",
            "title": "Missing CSP on /",
            "confidence": 0.72,
            "check": "security_header",
            "target": {"path": "/"},
            "parameters": {"header": "Content-Security-Policy"},
        },
        {
            "finding_id": "OC-2",
            "title": "Missing CSP on /secure (likely false positive)",
            "confidence": 0.63,
            "check": "security_header",
            "target": {"path": "/secure"},
            "parameters": {"header": "Content-Security-Policy"},
        },
        {
            "finding_id": "OC-3",
            "title": "Query input reflected on /search",
            "confidence": 0.80,
            "check": "reflection",
            "target": {"path": "/search"},
            "parameters": {"param": "q"},
        },
        {
            "finding_id": "OC-4",
            "title": "TRACE method appears enabled",
            "confidence": 0.55,
            "check": "http_method",
            "target": {"path": "/"},
            "parameters": {"method": "TRACE"},
        },
    ]

    # Launch Enigma as an MCP server from src/ (server-side allowlist: 127.0.0.1).
    env = dict(os.environ, PYTHONPATH=str(SRC))
    command = [sys.executable, "-m", "enigma", "mcp", "--allow-host", "127.0.0.1"]

    print(f"→ Authorized local target running at {base}")
    print("→ Launching Enigma as an MCP server: `enigma mcp --allow-host 127.0.0.1`\n")

    try:
        with MCPStdioClient(command, env=env) as client:
            info = client.server_info.get("serverInfo", {})
            print(f"Connected to MCP server: {info.get('name')} v{info.get('version')}")
            print("Tools:", ", ".join(t["name"] for t in client.list_tools()))

            # 1) OpenClaw checks the target is authorized/in scope first.
            decision = client.call_tool("validate_scope", {"assessment": assessment})
            print(f"\nvalidate_scope → allowed={decision['allowed']}  ({decision['reason']})")
            if not decision["allowed"]:
                print("Target not authorized/in scope — aborting.")
                return 1

            # 2) OpenClaw submits its hypotheses; Enigma proves or disproves them.
            report = client.call_tool(
                "verify_findings", {"assessment": assessment, "findings": findings}
            )

            print("\n=== Enigma verdicts (AI finds, Enigma verifies) ===")
            for r in report["results"]:
                print(
                    f"  {r['finding_id']:5}  {r['verdict']:14}  "
                    f"repro={str(r['reproducible']):5}  "
                    f"ai={r['finding']['ai_confidence']:.2f}  "
                    f"→ {r['finding']['title']}"
                )

            s = report["summary"]
            print(
                f"\nSummary: {s['confirmed']} confirmed · "
                f"{s['not_confirmed']} not-confirmed (false positive) · "
                f"{s['inconclusive']} inconclusive  (of {s['total']})"
            )

            # 3) The report is retrievable later by assessment id.
            again = client.call_tool("get_result", {"assessment_id": "ASM-MCP-DEMO"})
            print(f"get_result → {again['summary']['confirmed']} confirmed (retrieved by id)")
    finally:
        target.shutdown()
        target.server_close()

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
