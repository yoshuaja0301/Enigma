#!/usr/bin/env python3
"""Five finders, one live target — and a verdict that flips when reality does.

Runs the whole pipeline against a real (throwaway, local) web server using
output from all four supported instruments plus OpenClaw:

    python examples/live-demo/five_finders_demo.py

What it demonstrates, in order:

1. **Claimed confidence and truth are orthogonal.** The highest-confidence
   finding (0.93) cannot be adjudicated at all; the lowest (0.30) is confirmed.
   A *High confidence* ZAP alert is refuted by the server itself.
2. **Per-source metrics** — how much of each finder's output survived proof.
3. **Report integrity** — the run manifest, and what it catches.
4. **"Prove it live"** — the target is *fixed mid-run* and the same finding is
   re-proven through `EnigmaService.prove()`, the exact call behind the ▶ button
   on `GET /report/{id}`. The verdict flips from CONFIRMED to NOT_CONFIRMED,
   while the stored report keeps its original record.

No network access and no install required.
"""

from __future__ import annotations

import json
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

HERE = Path(__file__).resolve().parent
SRC = HERE.parents[1] / "src"
sys.path.insert(0, str(SRC))

from enigma.agent.tools import (  # noqa: E402
    parse_nmap,
    parse_nuclei,
    parse_whatweb,
    parse_zap,
)
from enigma.evidence import verify_report  # noqa: E402
from enigma.service import EnigmaService  # noqa: E402

# The port baked into the sample instrument output. The demo rewrites it to
# whatever port the throwaway target actually gets, so the files stay readable
# as realistic tool output.
SAMPLE_PORT = "8901"


# --- the authorized demo target --------------------------------------------- #
class _Target(BaseHTTPRequestHandler):
    """A deliberately imperfect shop. `hardened` flips one of its flaws."""

    hardened = False
    protocol_version = "HTTP/1.1"

    def log_message(self, *args):
        return

    def _send(self, status, headers, body=b""):
        self.send_response(status)
        self.send_header("Server", "nginx/1.18.0")
        for key, value in headers:
            self.send_header(key, value)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        if body:
            self.wfile.write(body)

    def do_GET(self):
        path = self.path.split("?")[0]
        if path == "/secure":
            # This page really IS hardened — a scanner claiming otherwise is wrong.
            self._send(
                200,
                [
                    ("Content-Security-Policy", "default-src 'self'"),
                    ("X-Frame-Options", "DENY"),
                    ("X-Content-Type-Options", "nosniff"),
                ],
                b"<html><body>secure page</body></html>",
            )
        elif path == "/uploads/":
            self._send(
                200,
                [("Content-Type", "text/html")],
                b"<html><head><title>Index of /uploads</title></head><body>"
                b"<h1>Index of /uploads</h1><pre><a href='invoice.pdf'>invoice.pdf</a>"
                b"</pre></body></html>",
            )
        elif path == "/search":
            q = self.path.split("q=")[-1] if "q=" in self.path else ""
            self._send(
                200,
                [("Content-Type", "text/html")],
                f"<html><body>results for: {q}</body></html>".encode(),
            )
        else:
            # Home page: leaks a session cookie without flags, and (unless
            # hardened) can be framed by any other site.
            extra = [("X-Frame-Options", "DENY")] if type(self).hardened else []
            self._send(
                200,
                [("Content-Type", "text/html"), ("Set-Cookie", "sid=s3cr3t; Path=/")]
                + extra,
                b"<html><body><h1>Demo Shop</h1></body></html>",
            )

    def do_HEAD(self):
        self._send(200, [])

    def do_OPTIONS(self):
        self._send(200, [("Allow", "GET, HEAD, POST, OPTIONS")])


def _start_target(port=0):
    server = ThreadingHTTPServer(("127.0.0.1", port), _Target)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server, server.server_address[1]


# --- gather the findings ------------------------------------------------------ #
def collect_findings(port):
    """Parse all five finders' output, re-pointed at the live port."""

    def read(name):
        return HERE.joinpath(name).read_text(encoding="utf-8").replace(SAMPLE_PORT, str(port))

    findings = json.loads(read("openclaw.json"))
    for finding in findings:
        finding["source"] = "openclaw"
    findings += parse_nuclei(read("nuclei.jsonl"))
    findings += parse_zap(read("zap.json"))
    findings += parse_nmap(read("nmap.xml"))
    findings += parse_whatweb(read("whatweb.json"))
    return findings


def _rule(title):
    print(f"\n{'=' * 78}\n{title}\n{'=' * 78}")


def main():
    server, port = _start_target()
    base = f"http://127.0.0.1:{port}"
    assessment = json.loads(
        HERE.joinpath("assessment.json").read_text(encoding="utf-8").replace(SAMPLE_PORT, str(port))
    )
    findings = collect_findings(port)

    service = EnigmaService()
    report = service.verify(assessment, findings)

    _rule(f"1. FIVE FINDERS vs ONE LIVE TARGET  ({base})")
    icon = {"CONFIRMED": "PROVEN  ", "NOT_CONFIRMED": "REFUTED ", "INCONCLUSIVE": "undecided"}
    print(f"{'ID':<13} {'SOURCE':<9} {'CLAIM':>5}  {'VERDICT':<10} OBSERVED (fact)")
    print("-" * 78)
    for result in report["results"]:
        finding, proof = result["finding"], result["proof"]
        print(
            f"{result['finding_id']:<13} {finding['source']:<9} "
            f"{finding['ai_confidence']:>5.2f}  {icon[result['verdict']]:<10} "
            f"{proof['observation'][:36]}"
        )
    print("\nThe 0.93 claim could not be adjudicated; the 0.30 claim was proven true.")
    print("Claimed confidence is a hypothesis — the verdict comes from the reply.")

    _rule("2. PER SOURCE — how much of each finder's output survived proof")
    print(f"{'source':<10} {'n':>3} {'proven':>7} {'refuted':>8} {'undecided':>10} "
          f"{'rate':>6} {'avg claim':>10}")
    print("-" * 78)
    for name, stats in sorted(
        report["summary"]["by_source"].items(), key=lambda kv: -kv[1]["total"]
    ):
        rate = f"{stats['confirmation_rate']:.0%}" if stats["decided"] else "n/a"
        print(
            f"{name:<10} {stats['total']:>3} {stats['confirmed']:>7} "
            f"{stats['not_confirmed']:>8} {stats['undecided']:>10} {rate:>6} "
            f"{stats['avg_claimed_confidence']:>10.2f}"
        )
    print("\nRates divide by DECIDED findings — what Enigma could not judge is not")
    print("held against the finder. See docs/metrics.md.")

    _rule("3. IS THIS REPORT STILL THE ONE ENIGMA PRODUCED?")
    manifest = report["manifest"]
    print(f"  chain head : {manifest['chain_head']}")
    print(f"  binds      : {manifest['total']} findings, "
          f"{manifest['with_evidence']} with evidence, and the summary")
    print(f"  verify_report(report) -> {verify_report(report) or 'OK — intact'}")

    # Someone doctors the report so a refuted finding looks proven.
    forged = json.loads(json.dumps(report))
    victim = next(i for i, r in enumerate(forged["results"]) if r["verdict"] == "NOT_CONFIRMED")
    forged["results"][victim]["verdict"] = "CONFIRMED"
    print(f"  forging a refuted verdict -> {verify_report(forged)[0]}")

    # ...and rewrites the headline metric to match.
    forged2 = json.loads(json.dumps(report))
    forged2["summary"]["confirmation_rate"] = 0.99
    print(f"  rewriting a metric        -> {verify_report(forged2)[0]}")

    _rule("4. PROVE IT LIVE — the same button, after the target is fixed")
    stored = next(r for r in report["results"] if r["finding_id"] == "OC-001")
    print(f"  stored record for OC-001 : {stored['verdict']}")
    print(f"    {stored['proof']['observation']}")

    before = service.prove(assessment["assessment_id"], "OC-001")
    print(f"\n  ▶ Prove it live (now)    : {before['result']['verdict']}")
    print(f"    {before['proof']['observation']}")

    print("\n  ... the operator now fixes the site (adds X-Frame-Options) ...\n")
    server.shutdown()
    server.server_close()
    _Target.hardened = True
    server, _ = _start_target(port)

    after = service.prove(assessment["assessment_id"], "OC-001")
    print(f"  ▶ Prove it live (again)  : {after['result']['verdict']}")
    print(f"    {after['proof']['observation']}")
    for limit in after["proof"].get("limits", []):
        print(f"      - {limit}")

    stored_again = service.get_result(assessment["assessment_id"])
    still = next(r for r in stored_again["results"] if r["finding_id"] == "OC-001")
    print(f"\n  stored record is unchanged: {still['verdict']}")
    print("  Both are true: one is the record of the assessment, the other is now.")

    server.shutdown()
    server.server_close()
    return report


if __name__ == "__main__":  # pragma: no cover
    main()
