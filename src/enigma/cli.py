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
from .reporting import to_json, to_markdown
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
        print(to_json(results))
    else:
        print(to_markdown(results))
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
    p_verify.add_argument("--format", choices=["json", "md"], default="md", help="report format")
    p_verify.add_argument("--evidence-dir", default=None, help="directory to persist sanitized evidence")
    p_verify.add_argument(
        "--offline",
        action="store_true",
        help="use a fake transport (no network); useful for demos and dry runs",
    )
    p_verify.set_defaults(func=_cmd_verify)

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
