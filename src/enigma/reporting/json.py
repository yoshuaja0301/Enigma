"""JSON reporting."""

from __future__ import annotations

import json
from typing import Any, List, Optional

from ..explain import build_proof
from .summary import Summary, summarize


def result_to_dict(result: Any) -> dict:
    data = result.to_dict()
    # Attach a human-readable proof (the request/response receipt + plain
    # language) so every surface can show *why*, not just the verdict.
    data["proof"] = build_proof(result)
    return data


def build_report(results: List[Any], summary: Optional[Summary] = None) -> dict:
    summary = summary or summarize(results)
    return {
        "summary": summary.to_dict(),
        "results": [result_to_dict(r) for r in results],
    }


def to_json(results: List[Any], summary: Optional[Summary] = None, indent: int = 2) -> str:
    return json.dumps(build_report(results, summary), indent=indent, ensure_ascii=False)
