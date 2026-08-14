#!/usr/bin/env python3
"""Emit a POST /verify body from the live-demo fixtures, on stdout.

    python .claude/skills/run-enigma/scripts/build_payload.py > payload.json
    python .claude/skills/run-enigma/scripts/build_payload.py --port 9001

Parses all five finders' sample output (OpenClaw + Nuclei + ZAP + Nmap +
WhatWeb) and pairs it with the demo assessment, re-pointed at `--port`.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from demo_target import REPO, load_demo  # noqa: E402


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--port", type=int, default=8901)
    args = ap.parse_args()

    demo = load_demo()
    assessment = json.loads(
        (REPO / "examples" / "live-demo" / "assessment.json").read_text(encoding="utf-8")
        .replace(demo.SAMPLE_PORT, str(args.port))
    )
    json.dump({"assessment": assessment, "findings": demo.collect_findings(args.port)},
              sys.stdout)


if __name__ == "__main__":
    main()
