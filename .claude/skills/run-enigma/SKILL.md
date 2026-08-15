---
name: run-enigma
description: Launch and drive the Enigma app locally — the REST server with its dashboard and report UI, the CLI, or the MCP server — against a real throwaway target, including screenshots of the report page and the live re-check flow. Use whenever asked to run, start, serve, demo, or screenshot Enigma, to confirm a change works in the real app rather than in tests, or to reproduce a verdict by hand.
---

# Running Enigma

Enigma has three surfaces over one `EnigmaService` facade. Pick by what you need
to show:

| Surface | Command | Use when |
|---|---|---|
| REST + dashboard | `enigma serve` | the ask involves the UI, the ▶ button, or an HTTP client |
| CLI | `enigma verify` / `validate` / `prove` | a terminal-shaped answer is enough |
| MCP | `enigma mcp` | driving it as an AI agent would |

Everything needs a **target**. Never point a demo at a host you are not
authorized to assess — the gate will block it, but don't rely on that.

## 0. Preflight

```bash
which enigma || pip install -e ".[dev]"
python -m pytest -q          # full suite, no network needed (300 at time of writing)
```

## 1. Start the target

The repo ships a deliberately imperfect local shop. Keep it on **8901**: that is
the port baked into `examples/live-demo/*.json`, so the sample Nuclei/ZAP/Nmap/
WhatWeb output is usable verbatim.

```bash
python .claude/skills/run-enigma/scripts/demo_target.py & echo $! > /tmp/enigma-target.pid
curl -sSI http://127.0.0.1:8901/                            # sanity
```

Record the PID like that for every background process here, and kill by PID.
Do **not** reach for `pkill -f` with any pattern you also typed in the same
command — `demo_target.py`, `enigma serve`, anything: `-f` matches whole
command lines, your own shell's included, so it kills the shell mid-script and
the rest of your commands never run (exit 144, no output, nothing obvious).
`kill %1` is no better — job control is per-shell, and each tool call is a new
shell. (If your harness has real background-task management, prefer that
over `&`; then stop tasks through it and skip the PID files.)

Its flaws are real and observable: framable home page, `Set-Cookie` with no
flags, a directory index at `/uploads/`, a version-disclosing `Server` header —
and a genuinely hardened `/secure`, which is what refutes the scanner alerts
that claim otherwise.

## 2. Serve, and prove the gate closes first

```bash
ENIGMA_API_TOKEN=demo-secret enigma serve --port 8737 --allow-host 127.0.0.1 \
  & echo $! > /tmp/enigma-api.pid
curl -sS http://127.0.0.1:8737/health
```

Before showing anything else, show what it refuses — this is the framework's
whole premise:

```bash
curl -sS -o- -w " %{http_code}\n" -X POST http://127.0.0.1:8737/verify -d '{}'
# → {"error": "unauthorized"} 401

# A VALID token pointed off-allowlist is still refused, and sends no request:
curl -sS -X POST http://127.0.0.1:8737/verify \
  -H 'Authorization: Bearer demo-secret' -H 'Content-Type: application/json' \
  -d '{"assessment":{"assessment_id":"X","target":{"url":"https://example.com/"},
       "authorization":{"status":"authorized"},"scope":{"allowed_hosts":["example.com"]}},
       "findings":[]}'
# → 403 target host 'example.com' is not in the server allowlist
```

## 3. Verify, with all five finders

```bash
python .claude/skills/run-enigma/scripts/build_payload.py > /tmp/payload.json
curl -sS -X POST http://127.0.0.1:8737/verify \
  -H 'Authorization: Bearer demo-secret' -H 'Content-Type: application/json' \
  --data-binary @/tmp/payload.json -o /tmp/report.json -w "HTTP %{http_code}\n"
```

The response body is `{summary, manifest, results}` — **no `assessment_id` at
the top level** (it is in the request; `GET /results/{id}` retrieves it later).
Read the two numbers that make the point:

```bash
python -c "
import json; s=json.load(open('/tmp/report.json'))['summary']
print('confirmed', s['confirmed'], '| refuted', s['not_confirmed'], '| undecided', s['inconclusive'])
print('avg claimed conf — CONFIRMED', s['avg_ai_confidence_confirmed'],
      'vs REFUTED', s['avg_ai_confidence_not_confirmed'])"
```

Expect refuted findings to average a *higher* claimed confidence than confirmed
ones. That is the result, not a bug.

## 4. The ▶ Prove it live button

`POST /prove` is exactly what the button on `GET /report/{id}` calls.

```bash
curl -sS -X POST http://127.0.0.1:8737/prove -H 'Authorization: Bearer demo-secret' \
  -H 'Content-Type: application/json' \
  -d '{"assessment_id":"ASM-LIVE-DEMO","finding_id":"OC-001"}' | python -c "
import json,sys; p=json.load(sys.stdin)
print(p['result']['verdict'], '—', p['proof']['observation'])
e=p['proof']['exchanges'][0]          # NOT proof['request'] — it lives here
print(e['request'], '->', e['response_status'], dict(e['response_headers']))"
```

Note `Set-Cookie: [REDACTED]` in the exchange: the sanitizer runs on live proofs
too, not only on stored evidence.

**To show the verdict flipping**, restart the target hardened and press again:

```bash
kill "$(cat /tmp/enigma-target.pid)"; sleep 1
python .claude/skills/run-enigma/scripts/demo_target.py --hardened & echo $! > /tmp/enigma-target.pid
# same prove call → NOT_CONFIRMED "The page is protected against framing."
curl -sS http://127.0.0.1:8737/results/ASM-LIVE-DEMO -H 'Authorization: Bearer demo-secret' \
  | grep -o '"verdict": "[A-Z_]*"' | head -1
# stored record still CONFIRMED — the report is never silently rewritten
```

The port rebinds immediately (`allow_reuse_address`), so the assessment stays
valid across the restart.

## 5. Screenshots

**The dashboard requires the `Authorization` header and has no `?token=`
escape hatch**, so a browser cannot open a token-protected instance. For visual
work, run a second, tokenless instance on loopback and seed it:

```bash
enigma serve --port 8738 --allow-host 127.0.0.1 & echo $! > /tmp/enigma-ui.pid
curl -sS -X POST http://127.0.0.1:8738/verify -H 'Content-Type: application/json' \
  --data-binary @/tmp/payload.json -o /dev/null

S=.claude/skills/run-enigma/scripts/shoot.sh
$S http://127.0.0.1:8738/ /tmp/dashboard.png 1280 700
$S http://127.0.0.1:8738/report/ASM-LIVE-DEMO /tmp/report.png 1280 1500
$S http://127.0.0.1:8738/report/ASM-LIVE-DEMO /tmp/card.png 1280 1150 1180  # scrolled to the cards
$S "http://127.0.0.1:8738/report/ASM-LIVE-DEMO?lang=id" /tmp/card-id.png 1280 1150 1180
```

That last offset is content-dependent — the summary and by-source tables grow
with the finding set — so read the PNG and nudge it if the first card is
clipped.

Then **look at the PNG** with Read. A blank frame means the page never loaded.
The finding card is the money shot: both confidence bars, the two probes, the
decisive line, and the ▶ button.

Gotchas already paid for, don't rediscover:

- Chromium lives at `/opt/pw-browsers/chromium-*/chrome-linux/chrome`; needs
  `--no-sandbox`. Its dbus/GPU errors on stderr are noise, not failure.
- `--screenshot` always captures from the top and cannot click. To capture
  further down, `shoot.sh` wraps the page in a **same-origin** iframe — a
  cross-origin one silently refuses to scroll.
- Playwright is not installed, and `chromium-cli` does not exist here.

## 6. CLI and MCP, if that is what was asked

Everything except `validate` sends real probes, so the §1 target must be up.

```bash
D=examples/live-demo
enigma validate --assessment $D/assessment.json          # gate only, no probes, no target needed
enigma verify --assessment $D/assessment.json --findings $D/openclaw.json --format md
enigma verify --assessment $D/assessment.json --nuclei $D/nuclei.jsonl \
  --zap $D/zap.json --nmap $D/nmap.xml --whatweb $D/whatweb.json --format md
enigma prove --assessment $D/assessment.json --findings $D/openclaw.json --id OC-001 --lang id
enigma verify --assessment $D/assessment.json --findings $D/openclaw.json --format md --lang id
python examples/mcp/openclaw_agent_demo.py    # MCP end to end, starts its own target
```

`--offline` swaps in a fake transport for any of these — useful for a dry run,
useless as evidence the app works.

## 7. Clean up

Kill every background process and confirm the ports are free; leaving 8901 bound
makes the next run verify against a stale target.

```bash
for f in /tmp/enigma-target.pid /tmp/enigma-api.pid /tmp/enigma-ui.pid; do
  [ -f "$f" ] && kill "$(cat "$f")" 2>/dev/null; rm -f "$f"
done
sleep 1
for p in 8737 8738 8901 8099; do
  if curl -sS -o /dev/null --max-time 2 "http://127.0.0.1:$p/" 2>/dev/null
    then echo "port $p STILL UP"; else echo "port $p down"; fi
done
```
