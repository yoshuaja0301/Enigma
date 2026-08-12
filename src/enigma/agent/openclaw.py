"""OpenClaw agent adapter.

OpenClaw is the *AI assessor*: it proposes potential findings. Enigma never lets
OpenClaw decide what is confirmed or what is in scope — it only consumes
proposals through this adapter. The concrete integration (HTTP call, local
model, message queue, ...) is intentionally out of scope; Enigma depends only on
the small :class:`OpenClawAdapter` interface.

``StaticOpenClawAdapter`` is provided so findings can be supplied from a file or
list, which is how the CLI and tests feed proposals into the pipeline.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, Iterable, List, Protocol, Union, runtime_checkable

from ..core.assessment import Assessment


@runtime_checkable
class OpenClawAdapter(Protocol):
    """Interface Enigma expects from any AI finding source."""

    def get_findings(self, assessment: Assessment) -> List[Dict[str, Any]]:
        """Return a list of raw (un-normalized) potential findings."""
        ...


class StaticOpenClawAdapter:
    """An adapter backed by a fixed list of raw findings.

    Useful for replaying OpenClaw output captured to a file, for tests, and for
    offline evaluation of the verification layer.
    """

    def __init__(self, findings: Iterable[Dict[str, Any]]) -> None:
        self._findings = [dict(f) for f in findings]

    def get_findings(self, assessment: Assessment) -> List[Dict[str, Any]]:  # noqa: ARG002
        return [dict(f) for f in self._findings]

    @classmethod
    def from_file(cls, source: Union[str, Path]) -> "StaticOpenClawAdapter":
        path = Path(source)
        with path.open("r", encoding="utf-8") as handle:
            data = json.load(handle)
        return cls(cls._coerce(data))

    @classmethod
    def from_data(cls, data: Any) -> "StaticOpenClawAdapter":
        return cls(cls._coerce(data))

    @staticmethod
    def _coerce(data: Any) -> List[Dict[str, Any]]:
        # Accept either a bare list of findings, or an object wrapping them.
        if isinstance(data, dict):
            if "findings" in data:
                data = data["findings"]
            else:
                data = [data]
        if not isinstance(data, list):
            raise ValueError("findings source must be a list or an object with a 'findings' array")
        return [dict(item) for item in data]
