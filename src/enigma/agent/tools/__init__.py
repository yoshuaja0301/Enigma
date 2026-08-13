"""Parsers that turn security-tool output into Enigma findings.

Tools like Nuclei and OWASP ZAP are **finders**, exactly like OpenClaw: they
report what they *suspect*. Their output therefore enters through the same
adapter seam and is still subject to Enigma's verification before it can affect
a verdict or the RAV.

Two consequences that are deliberate, not incidental:

* A tool's own severity/confidence is carried into the finding's ``confidence``
  field — the *hypothesis* slot. Verification never reads it, so a tool cannot
  talk Enigma into a verdict any more than an AI can.
* A tool finding that maps onto one of Enigma's safe checks is verified
  automatically; anything else is kept with status ``reported`` (never dropped,
  never probed unsafely).

Scope still applies: if a tool reports a URL outside the assessment's declared
scope, the authorization gate blocks it and nothing is sent.
"""

from __future__ import annotations

from typing import Any, Dict, List

from ...core.assessment import Assessment
from .nmap import NmapParseError, parse_nmap
from .nuclei import parse_nuclei
from .whatweb import parse_whatweb
from .zap import parse_zap


class ToolFindingAdapter:
    """An :class:`OpenClawAdapter` backed by parsed tool output."""

    def __init__(self, findings: List[Dict[str, Any]], source: str = "tool") -> None:
        self._findings = [dict(f) for f in findings]
        self._source = source

    def get_findings(self, assessment: Assessment) -> List[Dict[str, Any]]:  # noqa: ARG002
        return [dict(f) for f in self._findings]

    @property
    def source(self) -> str:
        return self._source

    @classmethod
    def from_nuclei(cls, source) -> "ToolFindingAdapter":
        return cls(parse_nuclei(source), source="nuclei")

    @classmethod
    def from_zap(cls, source) -> "ToolFindingAdapter":
        return cls(parse_zap(source), source="zap")

    @classmethod
    def from_nmap(cls, source) -> "ToolFindingAdapter":
        return cls(parse_nmap(source), source="nmap")

    @classmethod
    def from_whatweb(cls, source) -> "ToolFindingAdapter":
        return cls(parse_whatweb(source), source="whatweb")


# tool key -> parser, so callers can dispatch by name.
PARSERS = {
    "nuclei": parse_nuclei,
    "zap": parse_zap,
    "nmap": parse_nmap,
    "whatweb": parse_whatweb,
}

__all__ = [
    "parse_nuclei",
    "parse_zap",
    "parse_nmap",
    "parse_whatweb",
    "NmapParseError",
    "PARSERS",
    "ToolFindingAdapter",
]
