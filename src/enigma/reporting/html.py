"""HTML reporting.

Renders a verification report as a single, self-contained HTML document:
inline CSS, no external assets, no JavaScript required, theme-aware (light/dark)
and responsive. Every dynamic value is HTML-escaped, because findings originate
from an AI/external source.

Two renderers:

* ``render_report_html(report)``  — full report from a report dict
  (``{"summary": {...}, "results": [...]}``, as produced by
  :func:`enigma.reporting.json.build_report`).
* ``render_dashboard_html(entries)`` — a small index page listing stored
  assessments (used by the ``enigma serve`` dashboard).

``to_html(results, summary=None)`` is the convenience entry point that mirrors
``to_json`` / ``to_markdown`` and accepts result objects.
"""

from __future__ import annotations

from html import escape
from typing import Any, Dict, List, Optional

from .json import build_report

_VERDICT_META = {
    "CONFIRMED": ("confirmed", "✓", "Confirmed"),
    "NOT_CONFIRMED": ("not-confirmed", "✕", "Not confirmed"),
    "INCONCLUSIVE": ("inconclusive", "!", "Inconclusive"),
}

_CSS = """
:root {
  --bg: #f5f6f8; --surface: #ffffff; --surface-2: #fafbfc;
  --text: #1a1d21; --muted: #5b6572; --border: #e4e7ec;
  --accent: #3b5bdb;
  --ok: #12855a; --ok-bg: #e5f4ec;
  --bad: #c5372c; --bad-bg: #fbe9e7;
  --warn: #b9770a; --warn-bg: #fdf3e0;
  --neutral: #6b7280; --neutral-bg: #eef0f3;
  --shadow: 0 1px 2px rgba(16,24,40,.06), 0 1px 3px rgba(16,24,40,.05);
}
@media (prefers-color-scheme: dark) {
  :root {
    --bg: #0f1216; --surface: #171b21; --surface-2: #1c212a;
    --text: #e6e8eb; --muted: #9aa4b2; --border: #262c34;
    --accent: #7aa2ff;
    --ok: #46c78a; --ok-bg: #10241b;
    --bad: #f28b82; --bad-bg: #2a1613;
    --warn: #f5b955; --warn-bg: #2a2010;
    --neutral: #9aa4b2; --neutral-bg: #20252e;
    --shadow: 0 1px 2px rgba(0,0,0,.3);
  }
}
* { box-sizing: border-box; }
body {
  margin: 0; background: var(--bg); color: var(--text);
  font: 15px/1.55 -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
  -webkit-font-smoothing: antialiased;
}
.wrap { max-width: 1000px; margin: 0 auto; padding: 32px 20px 64px; }
header.masthead { display: flex; align-items: baseline; gap: 12px; flex-wrap: wrap; margin-bottom: 4px; }
.logo { font-weight: 700; font-size: 22px; letter-spacing: -.01em; }
.logo .mark { color: var(--accent); }
.subtitle { color: var(--muted); font-size: 14px; }
h2 { font-size: 15px; text-transform: uppercase; letter-spacing: .06em; color: var(--muted); margin: 32px 0 12px; }
.kpis { display: grid; grid-template-columns: repeat(auto-fit, minmax(140px, 1fr)); gap: 12px; }
.kpi { background: var(--surface); border: 1px solid var(--border); border-radius: 12px; padding: 14px 16px; box-shadow: var(--shadow); }
.kpi .n { font-size: 28px; font-weight: 700; line-height: 1.1; }
.kpi .l { color: var(--muted); font-size: 13px; margin-top: 2px; }
.kpi.ok .n { color: var(--ok); } .kpi.bad .n { color: var(--bad); }
.kpi.warn .n { color: var(--warn); } .kpi.neutral .n { color: var(--neutral); }
.card {
  background: var(--surface); border: 1px solid var(--border); border-left: 4px solid var(--neutral);
  border-radius: 12px; padding: 16px 18px; margin: 12px 0; box-shadow: var(--shadow);
}
.card.confirmed { border-left-color: var(--ok); }
.card.not-confirmed { border-left-color: var(--bad); }
.card.inconclusive { border-left-color: var(--warn); }
.card-head { display: flex; align-items: center; gap: 10px; flex-wrap: wrap; }
.badge { display: inline-flex; align-items: center; gap: 6px; font-size: 12px; font-weight: 600;
  padding: 3px 9px; border-radius: 999px; white-space: nowrap; }
.badge.confirmed { color: var(--ok); background: var(--ok-bg); }
.badge.not-confirmed { color: var(--bad); background: var(--bad-bg); }
.badge.inconclusive { color: var(--warn); background: var(--warn-bg); }
.fid { font-family: ui-monospace, SFMono-Regular, Menlo, monospace; font-size: 13px; color: var(--muted); }
.title { font-weight: 600; }
.meta { display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); gap: 8px 18px; margin: 12px 0 6px; }
.meta .k { color: var(--muted); font-size: 12px; }
.meta .v { font-size: 14px; }
.mono { font-family: ui-monospace, SFMono-Regular, Menlo, monospace; }
.bars { margin: 8px 0; }
.bar-row { display: grid; grid-template-columns: 130px 1fr 48px; align-items: center; gap: 10px; margin: 4px 0; font-size: 12px; color: var(--muted); }
.track { height: 8px; border-radius: 999px; background: var(--neutral-bg); overflow: hidden; }
.fill { height: 100%; border-radius: 999px; }
.fill.ai { background: var(--accent); }
.fill.enigma { background: var(--ok); }
.reason { color: var(--muted); font-size: 13px; margin-top: 6px; }
.chips { margin-top: 8px; display: flex; flex-wrap: wrap; gap: 6px; }
.chip { font-size: 12px; padding: 2px 8px; border-radius: 6px; background: var(--surface-2); border: 1px solid var(--border); color: var(--muted); }
.chip.osstmm { color: var(--accent); border-color: color-mix(in srgb, var(--accent) 30%, var(--border)); }
details { margin-top: 10px; }
summary { cursor: pointer; font-size: 13px; color: var(--muted); }
pre { background: var(--surface-2); border: 1px solid var(--border); border-radius: 8px; padding: 10px 12px;
  overflow-x: auto; font-size: 12px; margin: 8px 0 0; }
.cov-row { display: grid; grid-template-columns: 220px 1fr 32px; align-items: center; gap: 10px; margin: 6px 0; font-size: 13px; }
footer { margin-top: 40px; color: var(--muted); font-size: 12px; border-top: 1px solid var(--border); padding-top: 14px; }
a { color: var(--accent); }
table.idx { width: 100%; border-collapse: collapse; }
table.idx th, table.idx td { text-align: left; padding: 10px 12px; border-bottom: 1px solid var(--border); font-size: 14px; }
table.idx th { color: var(--muted); font-size: 12px; text-transform: uppercase; letter-spacing: .05em; }
.empty { color: var(--muted); background: var(--surface); border: 1px dashed var(--border); border-radius: 12px; padding: 24px; text-align: center; }
.plain { margin: 10px 0; }
.plain .q { font-weight: 600; font-size: 13px; }
.plain .a { color: var(--muted); font-size: 13px; margin-bottom: 6px; }
.proof { margin-top: 12px; border-top: 1px solid var(--border); padding-top: 12px; }
.proof h4 { margin: 0 0 6px; font-size: 12px; text-transform: uppercase; letter-spacing: .05em; color: var(--muted); }
.decisive { background: var(--warn-bg); border-left: 3px solid var(--warn); padding: 8px 10px; border-radius: 6px; font-size: 13px; margin: 8px 0; }
.decisive.ok { background: var(--ok-bg); border-left-color: var(--ok); }
.decisive.bad { background: var(--bad-bg); border-left-color: var(--bad); }
.exchange { margin: 8px 0; }
.exchange .req { font-family: ui-monospace, monospace; font-size: 12px; color: var(--accent); word-break: break-all; }
.exchange .st { font-size: 12px; color: var(--muted); }
.prove-btn { cursor: pointer; font-size: 13px; font-weight: 600; color: #fff; background: var(--accent); border: none; border-radius: 8px; padding: 8px 14px; margin-top: 10px; }
.prove-btn:disabled { opacity: .6; cursor: default; }
.prove-out { margin-top: 10px; }
"""


def _doc(title: str, body: str) -> str:
    return (
        "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\">"
        "<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">"
        f"<title>{escape(title)}</title><style>{_CSS}</style></head>"
        f"<body><div class=\"wrap\">{body}</div></body></html>"
    )


def _pct(value: Any) -> int:
    try:
        return max(0, min(100, round(float(value) * 100)))
    except (TypeError, ValueError):
        return 0


def _kpi(n: Any, label: str, cls: str = "") -> str:
    return f'<div class="kpi {cls}"><div class="n">{escape(str(n))}</div><div class="l">{escape(label)}</div></div>'


def _summary_block(summary: Dict[str, Any]) -> str:
    conf_rate = _pct(summary.get("confirmation_rate", 0))
    fp_rate = _pct(summary.get("false_positive_rate", 0))
    tiles = [
        _kpi(summary.get("total", 0), "Findings"),
        _kpi(summary.get("confirmed", 0), "Confirmed", "ok"),
        _kpi(summary.get("not_confirmed", 0), "Not confirmed", "bad"),
        _kpi(summary.get("inconclusive", 0), "Inconclusive", "warn"),
        _kpi(summary.get("reported", 0), "Reported", "warn"),
        _kpi(summary.get("blocked", 0), "Blocked", "neutral"),
        _kpi(summary.get("reproducible", 0), "Reproducible"),
        _kpi(f"{conf_rate}%", "Confirmation rate", "ok"),
        _kpi(f"{fp_rate}%", "False-positive rate", "bad"),
    ]
    return '<h2>Summary</h2><div class="kpis">' + "".join(tiles) + "</div>"


def _bar(label: str, value: Any, kind: str) -> str:
    pct = _pct(value)
    return (
        f'<div class="bar-row"><span>{escape(label)}</span>'
        f'<span class="track"><span class="fill {kind}" style="width:{pct}%"></span></span>'
        f'<span>{pct}%</span></div>'
    )


def _finding_card(r: Dict[str, Any], interactive: bool = False) -> str:
    verdict = str(r.get("verdict", "INCONCLUSIVE"))
    cls, icon, label = _VERDICT_META.get(verdict, ("inconclusive", "!", verdict))
    finding = r.get("finding", {})
    target = r.get("target", {})
    verification = r.get("verification", {})
    methodology = r.get("methodology", {})
    evidence = r.get("evidence") or {}

    host = target.get("host") or "-"
    path = target.get("path") or "/"
    title = finding.get("title") or r.get("finding_id", "")

    parts: List[str] = []
    parts.append(f'<div class="card {cls}">')
    parts.append('<div class="card-head">')
    parts.append(f'<span class="badge {cls}">{icon} {escape(label)}</span>')
    parts.append(f'<span class="fid">{escape(str(r.get("finding_id", "")))}</span>')
    parts.append(f'<span class="title">{escape(str(title))}</span>')
    parts.append("</div>")

    # meta grid
    repro = "yes" if r.get("reproducible") else "no"
    proc = verification.get("procedure") or "-"
    status = verification.get("status") or "-"
    parts.append('<div class="meta">')
    parts.append(f'<div><div class="k">Target</div><div class="v mono">{escape(host)}{escape(path)}</div></div>')
    parts.append(f'<div><div class="k">Procedure</div><div class="v">{escape(str(proc))} ({escape(str(status))})</div></div>')
    parts.append(f'<div><div class="k">Reproducible</div><div class="v">{escape(repro)}</div></div>')
    parts.append(f'<div><div class="k">Probes run</div><div class="v">{escape(str(verification.get("probes_run", 0)))}</div></div>')
    parts.append("</div>")

    # confidence bars: AI hypothesis vs Enigma verification
    parts.append('<div class="bars">')
    parts.append(_bar("AI confidence", finding.get("ai_confidence", 0), "ai"))
    parts.append(_bar("Enigma confidence", r.get("confidence", 0), "enigma"))
    parts.append("</div>")

    reason = verification.get("reason") or r.get("reason")
    if reason:
        parts.append(f'<div class="reason">{escape(str(reason))}</div>')

    # OSSTMM + evidence chips
    chips: List[str] = []
    if methodology:
        chan = methodology.get("channel")
        section = methodology.get("section")
        if chan or section:
            chips.append(f'<span class="chip osstmm">OSSTMM · {escape(str(chan))} / {escape(str(section))}</span>')
        for control in methodology.get("controls", []) or []:
            chips.append(f'<span class="chip">{escape(str(control))}</span>')
    if evidence.get("evidence_id"):
        chips.append(f'<span class="chip">Evidence {escape(str(evidence["evidence_id"]))}</span>')
    if chips:
        parts.append('<div class="chips">' + "".join(chips) + "</div>")

    # plain language + proof receipt
    parts.append(_proof_block(r, interactive))

    # observations (collapsible, for the technical reader)
    observations = verification.get("observations") or []
    if observations:
        import json as _json

        pretty = escape(_json.dumps(observations, indent=2, ensure_ascii=False))
        parts.append(f"<details><summary>Raw observations ({len(observations)})</summary><pre>{pretty}</pre></details>")

    parts.append("</div>")
    return "".join(parts)


def _proof_block(r: Dict[str, Any], interactive: bool) -> str:
    proof = r.get("proof") or {}
    if not proof:
        return ""
    verdict = str(r.get("verdict", ""))
    decisive_cls = "ok" if verdict == "CONFIRMED" else ("bad" if verdict == "NOT_CONFIRMED" else "")

    parts: List[str] = ['<div class="plain">']
    if proof.get("what"):
        parts.append(f'<div class="q">What this means</div><div class="a">{escape(str(proof["what"]))}</div>')
    if proof.get("why"):
        parts.append(f'<div class="q">Why it matters</div><div class="a">{escape(str(proof["why"]))}</div>')
    parts.append("</div>")

    exchanges = proof.get("exchanges") or []
    if exchanges or proof.get("decisive"):
        parts.append('<div class="proof">')
        parts.append("<h4>Proof — what we sent and got back</h4>")
        if proof.get("how"):
            parts.append(f'<div class="a">{escape(str(proof["how"]))}</div>')
        for ex in exchanges[:2]:  # first probe is enough to show the receipt
            parts.append('<div class="exchange">')
            parts.append(f'<div class="req">→ {escape(str(ex.get("request", "")))}</div>')
            parts.append(f'<div class="st">← HTTP {escape(str(ex.get("response_status")))}</div>')
            headers = ex.get("response_headers") or {}
            if headers:
                import json as _json

                shown = escape(_json.dumps(headers, indent=2, ensure_ascii=False))
                parts.append(f"<details><summary>response headers</summary><pre>{shown}</pre></details>")
            body = (ex.get("body_excerpt") or "").strip()
            if body:
                parts.append(f"<pre>{escape(body[:400])}</pre>")
            parts.append("</div>")
        if proof.get("decisive"):
            parts.append(f'<div class="decisive {decisive_cls}">{escape(str(proof["decisive"]))}</div>')
        rep = proof.get("reproduced") or {}
        if rep.get("times"):
            consistent = "same result each time" if rep.get("consistent") else "results varied"
            parts.append(
                f'<div class="a">Repeated {escape(str(rep.get("times")))} time(s) — {consistent}.</div>'
            )

        if interactive:
            aid = escape(str(r.get("assessment_id", "")))
            fid = escape(str(r.get("finding_id", "")))
            parts.append(
                f'<button class="prove-btn" onclick="enigmaProve(this)" '
                f'data-aid="{aid}" data-fid="{fid}">▶ Prove it live</button>'
                f'<div class="prove-out" id="prove-{fid}"></div>'
            )
        parts.append("</div>")
    return "".join(parts)


_GRADE_CLASS = {
    "balanced": "confirmed",
    "adequate": "confirmed",
    "degraded": "inconclusive",
    "poor": "inconclusive",
    "critical": "not-confirmed",
}


def _rav_block(rav: Dict[str, Any]) -> str:
    """Render the OSSTMM RAV panel."""

    if not rav:
        return ""
    porosity = rav.get("porosity", {})
    controls = rav.get("controls", {})
    limitations = rav.get("limitations", {})
    basis = rav.get("basis", {})
    grade = str(rav.get("grade", ""))
    cls = _GRADE_CLASS.get(grade, "inconclusive")

    parts: List[str] = ['<h2>OSSTMM RAV — Risk Assessment Value</h2>']
    parts.append(f'<div class="card {cls}">')
    parts.append('<div class="card-head">')
    parts.append(
        f'<span class="badge {cls}">Actual Security {escape(str(rav.get("actual_security")))}%</span>'
    )
    parts.append(f'<span class="title">{escape(grade)}</span>')
    parts.append(f'<span class="fid">deficit {escape(str(rav.get("security_deficit")))}%</span>')
    parts.append("</div>")

    parts.append('<div class="bars">')
    parts.append(_bar("True Protection", (rav.get("true_protection") or 0) / 100.0, "enigma"))
    parts.append(_bar("True Coverage", (rav.get("true_coverage") or 0) / 100.0, "ai"))
    parts.append("</div>")

    parts.append('<div class="meta">')
    parts.append(
        f'<div><div class="k">Porosity (OpSec)</div><div class="v">{escape(str(porosity.get("total", 0)))}'
        f' <span class="k">(vis {escape(str(porosity.get("visibility", 0)))} · '
        f'acc {escape(str(porosity.get("access", 0)))} · '
        f'trust {escape(str(porosity.get("trust", 0)))})</span></div></div>'
    )
    parts.append(
        f'<div><div class="k">Controls evidenced</div><div class="v">'
        f'{escape(str(controls.get("total", 0)))} / 10</div></div>'
    )
    parts.append(
        f'<div><div class="k">Limitations (verified)</div><div class="v">'
        f'{escape(str(limitations.get("total", 0)))}</div></div>'
    )
    parts.append(
        f'<div><div class="k">Excluded (unverified)</div><div class="v">'
        f'{escape(str(rav.get("excluded_unverified", 0)))}</div></div>'
    )
    parts.append("</div>")

    chips: List[str] = []
    for cat, count in sorted((limitations.get("counts") or {}).items()):
        chips.append(f'<span class="chip">{escape(cat)}: {escape(str(count))}</span>')
    for missing in (controls.get("missing") or [])[:5]:
        chips.append(f'<span class="chip">missing control: {escape(str(missing))}</span>')
    if chips:
        parts.append('<div class="chips">' + "".join(chips) + "</div>")

    if basis.get("formula"):
        parts.append(f'<div class="reason mono">{escape(str(basis["formula"]))}</div>')
    parts.append(
        '<div class="reason">Computed from <strong>verified observations only</strong>: '
        "CONFIRMED findings become limitations, NOT_CONFIRMED findings evidence a control, "
        "and unverified findings are excluded and counted separately.</div>"
    )
    parts.append("</div>")
    return "".join(parts)


def _modules_block(modules: Dict[str, Any]) -> str:
    """OSSTMM module checklist: which of the 17 modules were exercised, by what."""

    if not modules or not modules.get("phases"):
        return ""
    covered = modules.get("covered_modules", 0)
    total = modules.get("total_modules", 0)
    pct = _pct(modules.get("ratio", 0))
    instruments = modules.get("instruments") or []

    parts: List[str] = ["<h2>OSSTMM module coverage</h2>"]
    parts.append('<div class="kpis">')
    parts.append(_kpi(f"{covered}/{total}", "Modules covered", "ok" if pct >= 50 else "warn"))
    parts.append(_kpi(f"{pct}%", "Methodology coverage"))
    if instruments:
        parts.append(_kpi(len(instruments), "Instruments"))
    parts.append("</div>")

    if instruments:
        chips = "".join(f'<span class="chip">{escape(str(i))}</span>' for i in instruments)
        parts.append(f'<div class="chips">{chips}</div>')

    parts.append('<table class="idx"><thead><tr><th>Phase</th><th>Module</th>'
                 "<th>Covered</th><th>By</th></tr></thead><tbody>")
    for phase in modules["phases"]:
        label = f"{phase['phase']} · {phase['name']}"
        for module in phase["modules"]:
            mark = "✅" if module["covered"] else "—"
            by = ", ".join(module.get("covered_by") or [])
            row_style = "" if module["covered"] else ' style="opacity:.6"'
            parts.append(
                f"<tr{row_style}><td>{escape(label)}</td>"
                f"<td>{module['number']}. {escape(str(module['name']))}</td>"
                f"<td>{mark}</td><td class=\"mono\">{escape(by)}</td></tr>"
            )
    parts.append("</tbody></table>")
    return "".join(parts)


def _coverage_block(coverage: Dict[str, Any]) -> str:
    if not coverage:
        return ""
    total = sum(coverage.values()) or 1
    rows = ['<h2>OSSTMM coverage</h2>']
    for section, count in sorted(coverage.items(), key=lambda kv: (-kv[1], kv[0])):
        pct = round(count / total * 100)
        rows.append(
            f'<div class="cov-row"><span>{escape(str(section))}</span>'
            f'<span class="track"><span class="fill ai" style="width:{pct}%"></span></span>'
            f'<span>{count}</span></div>'
        )
    return "".join(rows)


# Small runtime for the "Prove it live" button (served dashboard only).
_PROVE_JS = """
<script>
async function enigmaProve(btn){
  const aid = btn.getAttribute('data-aid'), fid = btn.getAttribute('data-fid');
  const out = document.getElementById('prove-' + fid);
  btn.disabled = true; const label = btn.textContent; btn.textContent = 'Proving…';
  out.textContent = '';
  try {
    const res = await fetch('/prove', {method:'POST', headers:{'Content-Type':'application/json'},
      body: JSON.stringify({assessment_id: aid, finding_id: fid})});
    const data = await res.json();
    if (!res.ok || data.error) { out.innerHTML = '<div class="decisive bad">'+(data.error||('HTTP '+res.status))+'</div>'; return; }
    const p = data.proof || {};
    let html = '<div class="decisive '+(p.proven?'ok':'bad')+'">Live re-check just now: '+ (p.decisive||'') +'</div>';
    (p.exchanges||[]).slice(0,1).forEach(function(ex){
      html += '<div class="exchange"><div class="req">→ '+ex.request+'</div><div class="st">← HTTP '+ex.response_status+'</div></div>';
    });
    const rep = p.reproduced||{}; if (rep.times) html += '<div class="a">Repeated '+rep.times+' time(s) just now.</div>';
    out.innerHTML = html;
  } catch (e) { out.innerHTML = '<div class="decisive bad">'+e+'</div>'; }
  finally { btn.disabled = false; btn.textContent = label; }
}
</script>
"""


def render_report_html(
    report: Dict[str, Any],
    title: str = "Enigma Assessment Report",
    subtitle: Optional[str] = None,
    interactive: bool = False,
) -> str:
    summary = report.get("summary", {})
    results = report.get("results", [])

    body: List[str] = []
    body.append('<header class="masthead"><span class="logo"><span class="mark">⬢</span> Enigma</span>')
    body.append(f'<span class="subtitle">{escape(title)}</span></header>')
    if subtitle:
        body.append(f'<div class="subtitle">{escape(subtitle)}</div>')

    body.append(_summary_block(summary))
    body.append(_rav_block(summary.get("rav", {})))

    body.append("<h2>Findings</h2>")
    if results:
        for r in results:
            body.append(_finding_card(r, interactive))
    else:
        body.append('<div class="empty">No findings were assessed.</div>')

    body.append(_coverage_block(summary.get("osstmm_coverage", {})))
    body.append(_modules_block(summary.get("osstmm_modules", {})))

    body.append(
        "<footer>Generated by <strong>Enigma</strong> — evidence-based verification for "
        "authorized web vulnerability assessment. Verdicts reflect controlled, non-destructive "
        "verification; evidence is sanitized.</footer>"
    )
    if interactive:
        body.append(_PROVE_JS)
    return _doc(title, "".join(body))


def to_html(results: List[Any], summary: Optional[Any] = None, title: str = "Enigma Assessment Report",
            subtitle: Optional[str] = None, instruments: Optional[List[str]] = None) -> str:
    return render_report_html(
        build_report(results, summary, instruments=instruments), title=title, subtitle=subtitle
    )


def render_dashboard_html(entries: List[Dict[str, Any]], title: str = "Enigma Dashboard") -> str:
    body: List[str] = []
    body.append('<header class="masthead"><span class="logo"><span class="mark">⬢</span> Enigma</span>')
    body.append('<span class="subtitle">Assessment dashboard</span></header>')

    if not entries:
        body.append('<div class="empty">No assessments have been verified yet. '
                    'POST an assessment to <span class="mono">/verify</span> to get started.</div>')
    else:
        rows = [
            "<table class=\"idx\"><thead><tr>"
            "<th>Assessment</th><th>Confirmed</th><th>Not confirmed</th><th>Inconclusive</th>"
            "<th>Total</th><th>Report</th></tr></thead><tbody>"
        ]
        for entry in entries:
            aid = escape(str(entry.get("assessment_id", "")))
            s = entry.get("summary", {})
            rows.append(
                f"<tr><td class=\"mono\">{aid}</td>"
                f"<td>{escape(str(s.get('confirmed', 0)))}</td>"
                f"<td>{escape(str(s.get('not_confirmed', 0)))}</td>"
                f"<td>{escape(str(s.get('inconclusive', 0)))}</td>"
                f"<td>{escape(str(s.get('total', 0)))}</td>"
                f"<td><a href=\"/report/{aid}\">View HTML</a> · <a href=\"/results/{aid}\">JSON</a></td></tr>"
            )
        rows.append("</tbody></table>")
        body.append("".join(rows))

    body.append("<footer>Enigma dashboard · served by <span class=\"mono\">enigma serve</span></footer>")
    return _doc(title, "".join(body))
