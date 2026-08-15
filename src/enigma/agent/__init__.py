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
from .tools import (
    PARSERS,
    NmapParseError,
    ToolFindingAdapter,
    parse_nmap,
    parse_nuclei,
    parse_whatweb,
    parse_zap,
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
    "ToolFindingAdapter",
    "parse_nuclei",
    "parse_zap",
    "parse_nmap",
    "parse_whatweb",
    "NmapParseError",
    "PARSERS",
]
