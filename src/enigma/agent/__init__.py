"""Adapters for AI finding sources (OpenClaw)."""

from .openclaw import (
    CallableOpenClawAdapter,
    HttpOpenClawAdapter,
    OpenClawAdapter,
    StaticOpenClawAdapter,
)
from .prompt import (
    build_openclaw_prompt,
    build_openclaw_request,
    coerce_findings,
    parse_openclaw_findings,
)

__all__ = [
    "OpenClawAdapter",
    "StaticOpenClawAdapter",
    "CallableOpenClawAdapter",
    "HttpOpenClawAdapter",
    "build_openclaw_prompt",
    "build_openclaw_request",
    "parse_openclaw_findings",
    "coerce_findings",
]
