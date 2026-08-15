#!/usr/bin/env python3
"""What a real OpenClaw adapter looks like — end to end.

This shows the *shape* of a real integration: an LLM-style OpenClaw proposes
findings as JSON, and Enigma verifies them against a real local target. The
"model" here is a stub so the demo runs with no API key; swap `stub_openclaw`
for a real call to your model (Claude, etc.) and nothing else changes.

    python examples/openclaw/custom_adapter_demo.py
"""

from __future__ import annotations

import json
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

SRC = Path(__file__).resolve().parents[2] / "src"
sys.path.insert(0, str(SRC))

from enigma.agent.openclaw import CallableOpenClawAdapter  # noqa: E402
from enigma.controller import AssessmentController  # noqa: E402
from enigma.core.configuration import load_assessment  # noqa: E402
from enigma.reporting import to_markdown  # noqa: E402


# --- a local target with observable traits (see other demos) ----------------- #
class _Target(BaseHTTPRequestHandler):
    def log_message(self, *a):
        return

    def do_GET(self):
        if self.path.startswith("/secure"):
            self.send_response(200)
            self.send_header("Content-Security-Policy", "default-src 'self'")
            self.end_headers()
            self.wfile.write(b"secure")
        elif self.path.startswith("/search"):
            q = self.path.split("?", 1)[1] if "?" in self.path else ""
            self.send_response(200)
            self.end_headers()
            self.wfile.write(f"results for {q}".encode())
        else:
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"hello")

    def do_OPTIONS(self):
        self.send_response(200)
        self.send_header("Allow", "GET, HEAD, OPTIONS, TRACE")
        self.end_headers()


def _start_target():
    server = ThreadingHTTPServer(("127.0.0.1", 0), _Target)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server, server.server_address[1]


# --- the ONLY piece you replace with a real model ---------------------------- #
def stub_openclaw(prompt: str) -> str:
    """Stand-in for a real LLM call. Enigma passes it a prompt describing the
    target + supported checks; it must return findings JSON (a code fence is OK).

    Replace the body with a real call, e.g.:

        return client.messages.create(
            model="claude-...", max_tokens=2000,
            messages=[{"role": "user", "content": prompt}],
        ).content[0].text
    """
    findings = [
        {"finding_id": "OC-1", "title": "Missing CSP on /", "confidence": 0.72,
         "check": "security_header", "target": {"path": "/"},
         "parameters": {"header": "Content-Security-Policy"}},
        {"finding_id": "OC-2", "title": "Missing CSP on /secure", "confidence": 0.6,
         "check": "security_header", "target": {"path": "/secure"},
         "parameters": {"header": "Content-Security-Policy"}},
        {"finding_id": "OC-3", "title": "Reflected input on /search", "confidence": 0.8,
         "check": "reflection", "target": {"path": "/search"}, "parameters": {"param": "q"}},
    ]
    return "```json\n" + json.dumps(findings, indent=2) + "\n```"


def main() -> int:
    target, port = _start_target()
    base = f"http://127.0.0.1:{port}"

    assessment = load_assessment(
        {
            "assessment_id": "ASM-ADAPTER-DEMO",
            "target": {"url": base + "/"},
            "authorization": {"status": "authorized", "reference": "DEMO-ROE"},
            "scope": {"allowed_hosts": ["127.0.0.1"], "allowed_ports": [port]},
            "profile": "safe_verification",
        }
    )

    # This is the whole integration: an adapter that turns a model into findings.
    adapter = CallableOpenClawAdapter(stub_openclaw)

    print(f"→ Authorized local target at {base}")
    print("→ OpenClaw (stub model) proposes findings; Enigma verifies them.\n")

    try:
        results = AssessmentController(transport=None).run(assessment, adapter)  # real transport
    finally:
        target.shutdown()
        target.server_close()

    print(to_markdown(results))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
