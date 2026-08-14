#!/usr/bin/env python3
"""Run the live-demo target as a standalone, long-lived server.

`examples/live-demo/five_finders_demo.py` starts this target, drives it and
tears it down in one shot. To drive the app *by hand* — through `enigma serve`,
the dashboard, or curl — you need it to stay up, which is what this does.

    python .claude/skills/run-enigma/scripts/demo_target.py            # flawed
    python .claude/skills/run-enigma/scripts/demo_target.py --hardened # fixed

`--hardened` makes the home page send X-Frame-Options, which is how you flip a
CONFIRMED clickjacking finding to NOT_CONFIRMED on a live re-check. Restart the
process with the flag to simulate the operator shipping the fix; the port is
reusable immediately.
"""

from __future__ import annotations

import argparse
import importlib.util
import sys
import threading
from pathlib import Path

REPO = Path(__file__).resolve().parents[4]


def load_demo():
    sys.path.insert(0, str(REPO / "src"))
    path = REPO / "examples" / "live-demo" / "five_finders_demo.py"
    spec = importlib.util.spec_from_file_location("five_finders_demo", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    # 8901 is the port baked into examples/live-demo/*.json, so the sample
    # instrument output is usable verbatim with no rewriting.
    ap.add_argument("--port", type=int, default=8901)
    ap.add_argument("--hardened", action="store_true",
                    help="send X-Frame-Options on the home page (the 'fix')")
    args = ap.parse_args()

    demo = load_demo()
    demo._Target.hardened = args.hardened
    server, port = demo._start_target(args.port)
    state = "HARDENED" if args.hardened else "flawed"
    print(f"demo target ({state}) on http://127.0.0.1:{port}", flush=True)
    try:
        threading.Event().wait()
    except KeyboardInterrupt:
        pass
    finally:
        server.shutdown()
        server.server_close()


if __name__ == "__main__":
    main()
