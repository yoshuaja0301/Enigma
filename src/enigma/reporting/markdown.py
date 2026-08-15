"""Markdown reporting."""

from __future__ import annotations

from typing import Any, List, Optional

from ..explain import report_labels, translate_reason
from ..findings.model import Verdict
from .summary import Summary, summarize

_VERDICT_ICON = {
    Verdict.CONFIRMED: "✅",
    Verdict.NOT_CONFIRMED: "❌",
    Verdict.INCONCLUSIVE: "⚠️",
}


def _by_source_section(by_source: dict, t: dict) -> List[str]:
    """Per-finder outcomes: how much of each source's output survived proof."""

    if not by_source:
        return []
    lines = [
        f"## {t['by_source']}",
        "",
        t["by_source_note_md"],
        "",
        f"| {t['source']} | {t['findings']} | {t['confirmed']} | {t['not_confirmed']} "
        f"| {t['undecided']} | {t['confirmation_rate']} | {t['avg_claimed']} |",
        "|---|---|---|---|---|---|---|",
    ]
    for name, stats in sorted(by_source.items(), key=lambda kv: (-kv[1].total, kv[0])):
        rate = f"{stats.confirmation_rate:.0%}" if stats.decided else t["na"]
        lines.append(
            f"| `{name}` | {stats.total} | {stats.confirmed} | {stats.not_confirmed} | "
            f"{stats.undecided} | {rate} | {stats.avg_claimed_confidence:.2f} |"
        )
    lines.append("")
    return lines


def _manifest_section(manifest: Any, t: dict) -> List[str]:
    """Render the run manifest — the integrity record for this report."""

    if not manifest:
        return []
    data = manifest.to_dict() if hasattr(manifest, "to_dict") else dict(manifest)
    lines = [
        "",  # the preceding section ends on a table row; keep the heading separate
        f"## {t['manifest_heading']}",
        "",
        f"| {t['field']} | {t['value']} |",
        "|---|---|",
        f"| {t['generated_at']} | {data.get('generated_at', '-')} |",
        f"| {t['enigma_version']} | {data.get('enigma_version', '-')} |",
        f"| {t['python']} | {data.get('python_version', '-')} |",
        f"| {t['assessment']} | {data.get('assessment_id') or '-'} |",
        f"| {t['target']} | {data.get('target') or '-'} |",
        f"| {t['profile']} | {data.get('profile') or '-'} |",
        f"| {t['instruments']} | {', '.join(data.get('instruments') or []) or '-'} |",
        f"| {t['findings_recorded']} | {data.get('total', 0)} "
        f"({data.get('with_evidence', 0)} {t['with_evidence']}) |",
        f"| {t['digest']} | {data.get('digest_algorithm', '-')} |",
        f"| {t['chain_head']} | `{data.get('chain_head', '-')}` |",
        "",
        t["manifest_note_md"],
        "",
    ]
    return lines


def _rav_section(rav: dict, t: dict) -> List[str]:
    """Render the OSSTMM RAV block (empty when no RAV was computed)."""

    if not rav:
        return []
    porosity = rav.get("porosity", {})
    controls = rav.get("controls", {})
    limitations = rav.get("limitations", {})
    basis = rav.get("basis", {})

    lines = [f"## {t['rav_heading']}", ""]
    lines.append(f"| {t['metric']} | {t['value']} |")
    lines.append("|---|---|")
    lines.append(f"| **{t['actual_security']}** | **{rav.get('actual_security')} %** ({rav.get('grade')}) |")
    lines.append(f"| {t['security_deficit']} | {rav.get('security_deficit')} % |")
    lines.append(f"| {t['true_protection']} | {rav.get('true_protection')} % |")
    lines.append(f"| {t['true_coverage']} | {rav.get('true_coverage')} % |")
    lines.append(
        f"| {t['porosity']} | {porosity.get('total')} "
        f"({t['visibility']} {porosity.get('visibility')}, {t['access']} {porosity.get('access')}, "
        f"{t['trust']} {porosity.get('trust')}) |"
    )
    lines.append(f"| {t['controls_evidenced']} | {controls.get('total')} of 10 |")
    lines.append(f"| {t['limitations_verified']} | {limitations.get('total')} |")
    lines.append(f"| {t['excluded_unverified']} | {rav.get('excluded_unverified')} |")
    lines.append("")
    if limitations.get("counts"):
        breakdown = ", ".join(f"{k}: {v}" for k, v in sorted(limitations["counts"].items()))
        lines.append(f"{t['limitation_categories']} — {breakdown}.")
        lines.append("")
    if basis.get("formula"):
        lines.append(f"`{basis['formula']}`")
        lines.append("")
    lines.append("> " + t["rav_note_md"])
    lines.append("")
    return lines


def _modules_section(modules: dict, t: dict) -> List[str]:
    """Render the OSSTMM module checklist (phases A–D)."""

    if not modules or not modules.get("phases"):
        return []
    lines = ["", f"## {t['modules_heading']}", ""]
    instruments = modules.get("instruments") or []
    if instruments:
        lines.append(f"{t['instruments']}: {', '.join(instruments)}")
        lines.append("")
    covered, total = modules.get("covered_modules", 0), modules.get("total_modules", 0)
    lines.append(f"**{covered} / {total} {t['modules_covered_md']}** ({modules.get('ratio', 0):.0%})")
    lines.append("")
    lines.append(f"| {t['phase']} | {t['module']} | {t['covered']} | {t['by']} |")
    lines.append("|---|---|---|---|")
    for phase in modules["phases"]:
        for module in phase["modules"]:
            mark = "✅" if module["covered"] else "—"
            by = ", ".join(module.get("covered_by") or []) or ""
            lines.append(
                f"| {phase['phase']} · {phase['name']} | {module['number']}. {module['name']} "
                f"| {mark} | {by} |"
            )
    return lines


def to_markdown(
    results: List[Any],
    summary: Optional[Summary] = None,
    title: Optional[str] = None,
    instruments: Optional[List[str]] = None,
    manifest: Optional[Any] = None,
    lang: str = "en",
) -> str:
    t = report_labels(lang)
    title = title or t["report_title"]
    summary = summary or summarize(results, instruments=instruments)
    lines: List[str] = []
    lines.append(f"# {title}")
    lines.append("")
    lines.append(f"## {t['summary']}")
    lines.append("")
    lines.append(f"| {t['metric']} | {t['value']} |")
    lines.append("|---|---|")
    lines.append(f"| {t['findings_assessed']} | {summary.total} |")
    # The verdict names stay verbatim — they are the API's own vocabulary.
    lines.append(f"| CONFIRMED | {summary.confirmed} |")
    lines.append(f"| NOT_CONFIRMED | {summary.not_confirmed} |")
    lines.append(f"| INCONCLUSIVE | {summary.inconclusive} |")
    lines.append(f"| {t['reported_not_auto']} | {summary.reported} |")
    lines.append(f"| {t['blocked']} | {summary.blocked} |")
    lines.append(f"| {t['reproducible']} | {summary.reproducible} |")
    lines.append(f"| {t['confirmation_rate']} | {summary.confirmation_rate:.0%} |")
    lines.append(f"| {t['fp_rate']} | {summary.false_positive_rate:.0%} |")
    lines.append("")
    lines.extend(_by_source_section(summary.by_source, t))
    lines.extend(_rav_section(summary.rav, t))
    lines.append(f"## {t['findings']}")
    lines.append("")

    for result in results:
        icon = _VERDICT_ICON.get(result.verdict, "")
        title_text = result.finding.title or result.finding.finding_id
        lines.append(f"### {icon} {result.finding.finding_id} — {title_text}")
        lines.append("")
        lines.append(f"- **{t['verdict']}:** {result.verdict.value}")
        lines.append(f"- **{t['reproducible']}:** {t['yes'] if result.reproducible else t['no']}")
        lines.append(f"- **{t['verification_confidence']}:** {result.confidence:.2f}")
        lines.append(f"- **{t['ai_confidence']}:** {result.finding.confidence:.2f}")
        lines.append(f"- **{t['target']}:** `{result.finding.target_host or '-'}{result.finding.target_path}`")
        lines.append(f"- **{t['procedure']}:** {result.procedure or '-'} ({result.status})")
        if result.reason:
            lines.append(f"- **{t['reason']}:** {translate_reason(result.reason, lang)}")
        if result.methodology:
            controls = ", ".join(result.methodology.get("controls", []))
            lines.append(
                f"- **OSSTMM:** {result.methodology.get('channel')} / "
                f"{result.methodology.get('section')} — {controls}"
            )
        if result.evidence:
            lines.append(f"- **{t['evidence']}:** `{result.evidence.evidence_id}`")
        lines.append("")

    lines.extend(_modules_section(summary.osstmm_modules, t))
    lines.extend(_manifest_section(manifest, t))
    return "\n".join(lines)
