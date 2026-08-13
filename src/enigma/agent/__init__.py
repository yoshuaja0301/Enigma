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
from .tools import ToolFindingAdapter, parse_nuclei, parse_zap

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
]
