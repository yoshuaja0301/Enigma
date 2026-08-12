"""Loading and validating assessment configuration from disk or dicts."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Union

from .assessment import Assessment


def load_assessment(source: Union[str, Path, dict]) -> Assessment:
    """Load an :class:`Assessment` from a JSON file path or an already-parsed dict."""

    if isinstance(source, dict):
        return Assessment.from_dict(source)

    path = Path(source)
    if not path.exists():
        raise FileNotFoundError(f"assessment configuration not found: {path}")
    with path.open("r", encoding="utf-8") as handle:
        data = json.load(handle)
    return Assessment.from_dict(data)


def dump_assessment(assessment: Assessment) -> str:
    """Serialize an assessment back to canonical JSON."""

    return json.dumps(assessment.to_dict(), indent=2, ensure_ascii=False)
