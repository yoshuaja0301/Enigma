"""OSSTMM mapper.

Maps a verified finding onto the OSSTMM taxonomy: a channel, a section and the
operational controls it relates to. The mapping is keyed on the verification
``check`` (falling back to the finding category), so it stays stable regardless
of the free-text title an AI produced.
"""

from __future__ import annotations

from typing import Any, Dict, List

from ...findings.model import Finding, Verdict
from .controls import Control
from .taxonomy import WEB_CHANNEL, Section

# check -> (section, controls)
_CHECK_MAP = {
    "security_header": (Section.CONFIGURATION, [Control.CONFIDENTIALITY, Control.INTEGRITY]),
    "reflection": (Section.INTEGRITY, [Control.INTEGRITY, Control.SUBJUGATION]),
    "http_method": (Section.ACCESS_CONTROL, [Control.AUTHENTICATION, Control.SUBJUGATION]),
    "cookie_flags": (Section.CONFIDENTIALITY, [Control.CONFIDENTIALITY, Control.PRIVACY]),
    "cors": (Section.ACCESS_CONTROL, [Control.CONFIDENTIALITY, Control.SUBJUGATION]),
    "tls_redirect": (Section.CONFIDENTIALITY, [Control.CONFIDENTIALITY, Control.INTEGRITY]),
    "clickjacking": (Section.INTEGRITY, [Control.INTEGRITY, Control.SUBJUGATION]),
    "directory_listing": (Section.INFORMATION, [Control.CONFIDENTIALITY]),
    "server_version": (Section.INFORMATION, [Control.CONFIDENTIALITY]),
}

_DEFAULT_MAP = (Section.INFORMATION, [Control.CONFIDENTIALITY])


class OsstmmMapper:
    name = "OSSTMM"

    def map(self, finding: Finding, verdict: Verdict) -> Dict[str, Any]:
        section, controls = _CHECK_MAP.get(finding.check or "", _DEFAULT_MAP)
        return {
            "name": self.name,
            "channel": WEB_CHANNEL.value,
            "section": section.value,
            "controls": [c.value for c in controls],
            "verdict": verdict.value,
            "vector": self._vector(finding),
        }

    @staticmethod
    def _vector(finding: Finding) -> str:
        host = finding.target_host or "target"
        return f"{host}{finding.target_path}"

    def coverage(self, findings: List[Finding]) -> Dict[str, int]:
        """Count how many findings touched each section (coverage signal)."""

        counts: Dict[str, int] = {}
        for finding in findings:
            section, _ = _CHECK_MAP.get(finding.check or "", _DEFAULT_MAP)
            counts[section.value] = counts.get(section.value, 0) + 1
        return counts
