"""JSON reporting."""

from __future__ import annotations

import json
from typing import Any, List, Optional

from ..evidence.manifest import build_manifest
from ..explain import build_proof
from .summary import Summary, summarize


def result_to_dict(result: Any) -> dict:
    data = result.to_dict()
    # Attach a human-readable proof (the request/response receipt + plain
    # language) so every surface can show *why*, not just the verdict.
    data["proof"] = build_proof(result)
    return data


def build_report(
    results: List[Any],
    summary: Optional[Summary] = None,
    instruments: Optional[List[str]] = None,
    assessment: Optional[Any] = None,
    manifest: Optional[Any] = None,
) -> dict:
    """Assemble the report every surface renders.

    A run `manifest` is always included: it stamps the run and hash-chains the
    summary, every published finding and their evidence, so a reader can tell
    whether the report they hold is the one Enigma produced — check it with
    `enigma.evidence.verify_report`. Because it records a timestamp, two runs
    over identical input produce different `manifest.generated_at` and
    `chain_head` — that is the point. Pass `manifest` explicitly to reuse one.
    """

    summary = summary or summarize(results, instruments=instruments)
    records = [result_to_dict(r) for r in results]
    if manifest is None:
        manifest = build_manifest(
            results, assessment=assessment, records=records, summary=summary
        )
    return {
        "summary": summary.to_dict(),
        "manifest": manifest.to_dict() if hasattr(manifest, "to_dict") else manifest,
        "results": records,
    }


def to_json(
    results: List[Any],
    summary: Optional[Summary] = None,
    indent: int = 2,
    instruments: Optional[List[str]] = None,
    assessment: Optional[Any] = None,
    manifest: Optional[Any] = None,
) -> str:
    return json.dumps(
        build_report(
            results,
            summary,
            instruments=instruments,
            assessment=assessment,
            manifest=manifest,
        ),
        indent=indent,
        ensure_ascii=False,
    )
