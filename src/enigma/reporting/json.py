"""JSON reporting."""

from __future__ import annotations

import json
from typing import Any, List, Optional

from .summary import Summary, summarize


def result_to_dict(result: Any) -> dict:
    return result.to_dict()


def build_report(results: List[Any], summary: Optional[Summary] = None) -> dict:
    summary = summary or summarize(results)
    return {
        "summary": summary.to_dict(),
        "results": [result_to_dict(r) for r in results],
    }


def to_json(results: List[Any], summary: Optional[Summary] = None, indent: int = 2) -> str:
    return json.dumps(build_report(results, summary), indent=indent, ensure_ascii=False)
