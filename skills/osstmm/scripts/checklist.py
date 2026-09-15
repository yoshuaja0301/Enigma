#!/usr/bin/env python3
"""Generate an OSSTMM 3 audit worksheet for one or more channels.

The 17 modules are emitted in phase order with their purpose, completion
criterion and channel-specific checks, plus the porosity/limitation tally the
rav needs. Data comes from ../assets/modules.json.

Examples
--------
    python3 checklist.py --list-channels
    python3 checklist.py --channel data-networks
    python3 checklist.py --channel all --out audit/worksheets.md
    python3 checklist.py --channel wireless-communications --format json
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

DATA = Path(__file__).resolve().parent.parent / "assets" / "modules.json"


def load() -> dict:
    try:
        with DATA.open(encoding="utf-8") as fh:
            return json.load(fh)
    except FileNotFoundError:
        sys.exit(f"error: module data not found at {DATA}")
    except json.JSONDecodeError as exc:
        sys.exit(f"error: module data at {DATA} is not valid JSON: {exc}")


def resolve_channels(data: dict, requested: list[str]) -> list[dict]:
    by_id = {c["id"]: c for c in data["channels"]}
    if not requested or "all" in requested:
        return list(data["channels"])
    selected, unknown = [], []
    for name in requested:
        key = name.strip().lower()
        if key in by_id:
            selected.append(by_id[key])
        else:
            unknown.append(name)
    if unknown:
        sys.exit(
            "error: unknown channel(s): "
            + ", ".join(unknown)
            + "\nknown channels: "
            + ", ".join(by_id)
        )
    # de-duplicate while keeping the canonical order
    return [c for c in data["channels"] if c in selected]


def render_markdown(data: dict, channels: list[dict]) -> str:
    phases = {p["id"]: p for p in data["phases"]}
    out: list[str] = [
        "# OSSTMM 3 audit worksheet",
        "",
        f"Methodology: {data['methodology']} — {data['source']}",
        "",
        "Fill this in as the audit runs. A module is not done until its completion",
        "criterion holds; a limitation is not counted until it is verified against the",
        "live target with evidence attached.",
        "",
        "## Engagement record",
        "",
        "| Field | Value |",
        "| --- | --- |",
        "| Scope |  |",
        "| Exclusions |  |",
        "| Test type |  |",
        "| Window (start / end, TZ) |  |",
        "| Authorization reference |  |",
        "| Analyst(s) |  |",
        "| Abort contact |  |",
        "",
    ]

    for channel in channels:
        out += [
            f"## Channel: {channel['name']} ({channel['code']})",
            "",
            f"- Scope: {channel['scope']}",
            f"- Index by: {channel['index']}",
            "",
        ]
        for phase in data["phases"]:
            modules = [m for m in data["modules"] if m["phase"] == phase["id"]]
            if not modules:
                continue
            out += [
                f"### Phase {phase['id']} — {phase['name']}",
                "",
                f"_{phase['intent']}_",
                "",
            ]
            for module in modules:
                note = module["channel_notes"].get(channel["id"], "")
                out += [
                    f"#### [ ] {module['id']}. {module['name']}",
                    "",
                    f"- Purpose: {module['purpose']}",
                    f"- Done when: {module['done_when']}",
                ]
                if note:
                    out.append(f"- This channel: {note}")
                out += [
                    "- Findings / evidence refs:",
                    "- Not covered (and why):",
                    "",
                ]
        out += [
            f"### Tally — {channel['name']}",
            "",
            "Porosity (count pores, not hosts):",
            "",
            "| Porosity | Count |",
            "| --- | --- |",
            "| Visibility |  |",
            "| Access |  |",
            "| Trust |  |",
            "",
            "Controls, counted only where verified working (per pore, per type):",
            "",
            "| Class A (interactive) | Count | Class B (process) | Count |",
            "| --- | --- | --- | --- |",
            "| Authentication |  | Non-repudiation |  |",
            "| Indemnification |  | Confidentiality |  |",
            "| Resilience |  | Privacy |  |",
            "| Subjugation |  | Integrity |  |",
            "| Continuity |  | Alarm |  |",
            "",
            "Limitations, counted per affected target:",
            "",
            "| Limitation | Count |",
            "| --- | --- |",
            "| Vulnerability |  |",
            "| Weakness |  |",
            "| Concern |  |",
            "| Exposure |  |",
            "| Anomaly |  |",
            "",
            "Then: `python3 scripts/rav.py --visibility N --access N --trust N ...`",
            "",
        ]
    return "\n".join(out).rstrip() + "\n"


def render_json(data: dict, channels: list[dict]) -> str:
    payload = {
        "methodology": data["methodology"],
        "source": data["source"],
        "phases": data["phases"],
        "channels": [
            {
                **channel,
                "modules": [
                    {
                        "id": m["id"],
                        "phase": m["phase"],
                        "name": m["name"],
                        "purpose": m["purpose"],
                        "done_when": m["done_when"],
                        "channel_note": m["channel_notes"].get(channel["id"], ""),
                        "status": "not-started",
                        "evidence": [],
                    }
                    for m in data["modules"]
                ],
                "tally": {
                    "porosity": {"visibility": 0, "access": 0, "trust": 0},
                    "controls": {
                        "authentication": 0,
                        "indemnification": 0,
                        "resilience": 0,
                        "subjugation": 0,
                        "continuity": 0,
                        "non_repudiation": 0,
                        "confidentiality": 0,
                        "privacy": 0,
                        "integrity": 0,
                        "alarm": 0,
                    },
                    "limitations": {
                        "vulnerability": 0,
                        "weakness": 0,
                        "concern": 0,
                        "exposure": 0,
                        "anomaly": 0,
                    },
                },
            }
            for channel in channels
        ],
    }
    return json.dumps(payload, indent=2) + "\n"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Generate an OSSTMM 3 audit worksheet per channel."
    )
    parser.add_argument(
        "--channel",
        action="append",
        default=[],
        metavar="ID",
        help="channel id, repeatable; 'all' for every channel (default: all)",
    )
    parser.add_argument(
        "--format", choices=("md", "json"), default="md", help="output format"
    )
    parser.add_argument("--out", metavar="PATH", help="write to this file instead of stdout")
    parser.add_argument(
        "--list-channels", action="store_true", help="list channel ids and exit"
    )
    args = parser.parse_args(argv)

    data = load()

    if args.list_channels:
        for channel in data["channels"]:
            print(f"{channel['id']:<26} {channel['code']:<8} {channel['name']}")
        return 0

    channels = resolve_channels(data, args.channel)
    text = render_markdown(data, channels) if args.format == "md" else render_json(data, channels)

    if args.out:
        path = Path(args.out)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
        print(f"wrote {path} ({len(channels)} channel(s), {len(data['modules'])} modules each)")
    else:
        sys.stdout.write(text)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
