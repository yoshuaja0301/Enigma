"""Markdown reporting."""

from __future__ import annotations

from typing import Any, List, Optional

from ..findings.model import Verdict
from .summary import Summary, summarize

_VERDICT_ICON = {
    Verdict.CONFIRMED: "✅",
    Verdict.NOT_CONFIRMED: "❌",
    Verdict.INCONCLUSIVE: "⚠️",
}


def to_markdown(results: List[Any], summary: Optional[Summary] = None, title: str = "Enigma Assessment Report") -> str:
    summary = summary or summarize(results)
    lines: List[str] = []
    lines.append(f"# {title}")
    lines.append("")
    lines.append("## Summary")
    lines.append("")
    lines.append("| Metric | Value |")
    lines.append("|---|---|")
    lines.append(f"| Findings assessed | {summary.total} |")
    lines.append(f"| CONFIRMED | {summary.confirmed} |")
    lines.append(f"| NOT_CONFIRMED | {summary.not_confirmed} |")
    lines.append(f"| INCONCLUSIVE | {summary.inconclusive} |")
    lines.append(f"| Needs manual review | {summary.needs_manual_review} |")
    lines.append(f"| Blocked | {summary.blocked} |")
    lines.append(f"| Reproducible | {summary.reproducible} |")
    lines.append(f"| Confirmation rate | {summary.confirmation_rate:.0%} |")
    lines.append(f"| False-positive rate | {summary.false_positive_rate:.0%} |")
    lines.append("")
    lines.append("## Findings")
    lines.append("")

    for result in results:
        icon = _VERDICT_ICON.get(result.verdict, "")
        title_text = result.finding.title or result.finding.finding_id
        lines.append(f"### {icon} {result.finding.finding_id} — {title_text}")
        lines.append("")
        lines.append(f"- **Verdict:** {result.verdict.value}")
        lines.append(f"- **Reproducible:** {'yes' if result.reproducible else 'no'}")
        lines.append(f"- **Verification confidence:** {result.confidence:.2f}")
        lines.append(f"- **AI confidence:** {result.finding.confidence:.2f}")
        lines.append(f"- **Target:** `{result.finding.target_host or '-'}{result.finding.target_path}`")
        lines.append(f"- **Procedure:** {result.procedure or '-'} ({result.status})")
        if result.reason:
            lines.append(f"- **Reason:** {result.reason}")
        if result.methodology:
            controls = ", ".join(result.methodology.get("controls", []))
            lines.append(
                f"- **OSSTMM:** {result.methodology.get('channel')} / "
                f"{result.methodology.get('section')} — {controls}"
            )
        if result.evidence:
            lines.append(f"- **Evidence:** `{result.evidence.evidence_id}`")
        lines.append("")

    return "\n".join(lines)
