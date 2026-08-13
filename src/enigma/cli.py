"""Enigma command-line interface.

Subcommands:

    enigma validate --assessment ASSESSMENT.json
        Run only the authorization / scope / policy gate against the target and
        report ALLOWED or ASSESSMENT BLOCKED. Sends no probes.

    enigma verify --assessment ASSESSMENT.json --findings FINDINGS.json
                  [--format json|md] [--evidence-dir DIR] [--offline]
        Normalize the (OpenClaw) findings, verify each within scope/policy, map
        to OSSTMM and print a report.
"""

from __future__ import annotations

import argparse
import sys
from typing import List, Optional

import os

from .agent.openclaw import StaticOpenClawAdapter
from .authorization.validator import AuthorizationValidator
from .controller import AssessmentController
from .core.configuration import load_assessment
from .explain import build_proof
from .reporting import to_html, to_json, to_markdown
from .service import EnigmaService
from .verification.http import FakeTransport


def _cmd_validate(args: argparse.Namespace) -> int:
    assessment = load_assessment(args.assessment)
    validator = AuthorizationValidator(assessment)
    decision = validator.authorize(assessment.target.url, "GET")
    if decision.allowed:
        print(f"ALLOWED — {assessment.target.url}")
        print(f"  {decision.reason}")
        return 0
    print("ASSESSMENT BLOCKED")
    print(f"  target: {assessment.target.url}")
    print(f"  stage : {decision.stage.value}")
    print(f"  reason: {decision.reason}")
    return 2


def _cmd_verify(args: argparse.Namespace) -> int:
    assessment = load_assessment(args.assessment)
    adapter = StaticOpenClawAdapter.from_file(args.findings)

    transport = FakeTransport() if args.offline else None
    controller = AssessmentController(transport=transport, evidence_dir=args.evidence_dir)
    results = controller.run(assessment, adapter)

    if args.format == "json":
        rendered = to_json(results, instruments=list(assessment.instruments))
    elif args.format == "html":
        rendered = to_html(
            results,
            subtitle=f"Assessment {assessment.assessment_id} · target {assessment.target.url}",
            instruments=list(assessment.instruments),
        )
    else:
        rendered = to_markdown(results, instruments=list(assessment.instruments))

    if args.output:
        with open(args.output, "w", encoding="utf-8") as handle:
            handle.write(rendered)
        print(f"wrote {args.format} report to {args.output}")
    else:
        print(rendered)
    return 0


def _cmd_prove(args: argparse.Namespace) -> int:
    assessment = load_assessment(args.assessment)
    adapter = StaticOpenClawAdapter.from_file(args.findings)
    transport = FakeTransport() if args.offline else None
    results = AssessmentController(transport=transport).run(assessment, adapter)

    if args.id:
        results = [r for r in results if r.finding.finding_id == args.id]
        if not results:
            print(f"error: no finding with id {args.id!r}", file=sys.stderr)
            return 1

    icon = {"CONFIRMED": "PROVEN", "NOT_CONFIRMED": "not a problem", "INCONCLUSIVE": "unproven"}
    for r in results:
        proof = build_proof(r, lang=args.lang)
        print("=" * 72)
        verdict = r.verdict.value
        print(f"{r.finding.finding_id}  [{icon.get(verdict, verdict)}]  {proof['label']}")
        print(f"  What it means : {proof['what']}")
        print(f"  Why it matters: {proof['why']}")
        print(f"  How we checked: {proof['how']}")
        if proof["exchanges"]:
            print("  Proof (what we sent and got back):")
            for ex in proof["exchanges"][:2]:
                print(f"    → {ex['request']}")
                print(f"    ← HTTP {ex['response_status']}")
        print(f"  >> OBSERVED (fact): {proof['observation']}")
        rep = proof["reproduced"]
        print(f"  Repeated {rep['times']} time(s); {'same result each time' if rep['consistent'] else 'results varied'}.")
        if proof.get("limits"):
            print("  Limits of this verdict:")
            for limit in proof["limits"]:
                print(f"    - {limit}")
    print("=" * 72)
    return 0


def _cmd_serve(args: argparse.Namespace) -> int:
    from .integrations.http_api import run_server

    transport = FakeTransport() if args.offline else None
    service = EnigmaService(
        transport=transport,
        evidence_dir=args.evidence_dir,
        allowed_hosts=args.allow_host or None,
    )
    token = args.token or os.environ.get("ENIGMA_API_TOKEN")
    run_server(host=args.host, port=args.port, service=service, token=token)
    return 0


def _cmd_mcp(args: argparse.Namespace) -> int:
    from .integrations.mcp_server import EnigmaMcpServer

    transport = FakeTransport() if args.offline else None
    service = EnigmaService(
        transport=transport,
        evidence_dir=args.evidence_dir,
        allowed_hosts=args.allow_host or None,
    )
    EnigmaMcpServer(service=service).serve_stdio()
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="enigma",
        description="Evidence-based verification for authorized web vulnerability assessment.",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    p_validate = sub.add_parser("validate", help="check authorization/scope/policy only")
    p_validate.add_argument("--assessment", required=True, help="path to assessment JSON")
    p_validate.set_defaults(func=_cmd_validate)

    p_verify = sub.add_parser("verify", help="verify findings for an assessment")
    p_verify.add_argument("--assessment", required=True, help="path to assessment JSON")
    p_verify.add_argument("--findings", required=True, help="path to findings JSON (list or {findings:[...]})")
    p_verify.add_argument("--format", choices=["json", "md", "html"], default="md", help="report format")
    p_verify.add_argument("--output", default=None, help="write the report to a file instead of stdout")
    p_verify.add_argument("--evidence-dir", default=None, help="directory to persist sanitized evidence")
    p_verify.add_argument(
        "--offline",
        action="store_true",
        help="use a fake transport (no network); useful for demos and dry runs",
    )
    p_verify.set_defaults(func=_cmd_verify)

    p_prove = sub.add_parser("prove", help="verify findings and print a plain-language proof")
    p_prove.add_argument("--assessment", required=True, help="path to assessment JSON")
    p_prove.add_argument("--findings", required=True, help="path to findings JSON")
    p_prove.add_argument("--id", default=None, help="prove only this finding id")
    p_prove.add_argument("--lang", choices=["en", "id"], default="en", help="plain-language register")
    p_prove.add_argument("--offline", action="store_true", help="use a fake transport (no network)")
    p_prove.set_defaults(func=_cmd_prove)

    p_serve = sub.add_parser("serve", help="run the REST + webhook API server")
    p_serve.add_argument("--host", default="127.0.0.1", help="bind host (default 127.0.0.1)")
    p_serve.add_argument("--port", type=int, default=8737, help="bind port (default 8737)")
    p_serve.add_argument("--token", default=None, help="bearer token (or set ENIGMA_API_TOKEN)")
    p_serve.add_argument("--evidence-dir", default=None, help="directory to persist sanitized evidence")
    p_serve.add_argument(
        "--allow-host",
        action="append",
        default=[],
        help="server-side host allowlist (repeatable); blocks targets outside it",
    )
    p_serve.add_argument("--offline", action="store_true", help="use a fake transport (no network)")
    p_serve.set_defaults(func=_cmd_serve)

    p_mcp = sub.add_parser("mcp", help="run the MCP server over stdio (for AI agents)")
    p_mcp.add_argument("--evidence-dir", default=None, help="directory to persist sanitized evidence")
    p_mcp.add_argument(
        "--allow-host",
        action="append",
        default=[],
        help="server-side host allowlist (repeatable)",
    )
    p_mcp.add_argument("--offline", action="store_true", help="use a fake transport (no network)")
    p_mcp.set_defaults(func=_cmd_mcp)

    return parser


def main(argv: Optional[List[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return args.func(args)
    except FileNotFoundError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
