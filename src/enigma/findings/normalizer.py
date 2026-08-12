"""Finding normalizer.

Turns loosely-structured OpenClaw output into a consistent internal
:class:`Finding`. It is tolerant of missing fields and will try to infer the
verification ``check`` from hints in the raw finding, but it never invents a
check that cannot be safely run.
"""

from __future__ import annotations

import itertools
from typing import Any, Dict, Iterable, List, Optional

from .confidence import clamp
from .model import Finding

_counter = itertools.count(1)

# Recognized safe verification procedures. A finding whose check is not in this
# set is normalized with check=None, which yields an INCONCLUSIVE verdict rather
# than an unsafe or unknown probe.
KNOWN_CHECKS = frozenset({"security_header", "reflection", "http_method"})

# Map common OpenClaw category strings onto a default safe check.
_CATEGORY_CHECK_HINTS = {
    "missing_security_header": "security_header",
    "security_header": "security_header",
    "reflected_input": "reflection",
    "reflection": "reflection",
    "http_methods": "http_method",
    "http_method": "http_method",
}


class FindingNormalizer:
    """Normalizes raw finding dicts into :class:`Finding` objects."""

    def normalize(self, raw: Dict[str, Any]) -> Finding:
        finding_id = str(raw.get("finding_id") or raw.get("id") or self._next_id())

        target = raw.get("target") or {}
        if isinstance(target, str):
            target = {"host": target}

        check = self._resolve_check(raw)

        return Finding(
            finding_id=finding_id,
            category=str(raw.get("category", "web_application")),
            type=str(raw.get("type", "potential_vulnerability")),
            title=str(raw.get("title", "")),
            description=str(raw.get("description", "")),
            confidence=clamp(raw.get("confidence", 0.0)),
            target_host=target.get("host"),
            target_path=str(target.get("path", raw.get("path", "/")) or "/"),
            check=check,
            parameters=dict(raw.get("parameters", {})),
            source=str(raw.get("source", "openclaw")),
            raw=dict(raw),
        )

    def normalize_many(self, raws: Iterable[Dict[str, Any]]) -> List[Finding]:
        return [self.normalize(r) for r in raws]

    def _resolve_check(self, raw: Dict[str, Any]) -> Optional[str]:
        explicit = raw.get("check")
        if explicit and explicit in KNOWN_CHECKS:
            return str(explicit)
        # Fall back to a category hint.
        category = str(raw.get("category", "")).strip().lower()
        hinted = _CATEGORY_CHECK_HINTS.get(category)
        if hinted in KNOWN_CHECKS:
            return hinted
        return None

    @staticmethod
    def _next_id() -> str:
        return f"F-{next(_counter):05d}"
