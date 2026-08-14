# Live demo — five finders, one target, and a verdict that flips

```bash
python examples/live-demo/five_finders_demo.py
```

No install, no API key, no external network. The demo starts a throwaway web
server on `127.0.0.1`, feeds Enigma the output of **all five finders** at once,
and verifies every finding against that live target.

## What is in here

| File | What it is |
|---|---|
| `assessment.json` | the authorization, scope, profile and declared instruments |
| `openclaw.json` | what the AI agent proposed |
| `nuclei.jsonl` | `nuclei -jsonl` output |
| `zap.json` | an OWASP ZAP JSON report |
| `nmap.xml` | `nmap -sV -oX -` output |
| `whatweb.json` | `whatweb --log-json` output |
| `five_finders_demo.py` | the runnable demo |

The instrument files are realistic samples that mention port `8901`; the demo
rewrites that to whatever port the throwaway server actually gets, so the files
stay readable as tool output.

## What it shows

**1. Claimed confidence and truth are orthogonal.**

```
ID            SOURCE    CLAIM  VERDICT    OBSERVED (fact)
OC-002        openclaw   0.93  undecided  no automatic check for this finding
NUCLEI-0001   nuclei     0.30  PROVEN     The reply did NOT include the 'Conte
ZAP-0001      zap        0.85  REFUTED    The reply DID include 'Content-Secur
```

The most confident claim cannot be adjudicated at all; the least confident one
is true. A *High confidence* ZAP alert about `/secure` is refuted by the server,
which does send that header. The verdict is computed from the reply, never from
the number the finder asserted.

**2. Per-source metrics** — `summary.by_source`, with rates over *decided*
findings so that what Enigma could not judge is not counted against the finder.
See [`docs/metrics.md`](../../docs/metrics.md).

**3. Report integrity** — the run manifest, and what it catches:

```
verify_report(report)      -> OK — intact
forging a refuted verdict  -> published record 2 (OC-003) does not match its recorded digest
rewriting a metric         -> report summary does not match its recorded digest
```

**4. "Prove it live."** The demo *fixes the target mid-run* — the operator adds
`X-Frame-Options` — then re-proves the same finding through
`EnigmaService.prove()`, the exact call behind the ▶ button on
`GET /report/{id}`:

```
stored record for OC-001 : CONFIRMED
▶ Prove it live (now)    : CONFIRMED    the page can be framed
... the operator now fixes the site ...
▶ Prove it live (again)  : NOT_CONFIRMED  the page is protected against framing
stored record is unchanged: CONFIRMED
```

Both are true: one is the record of the assessment, the other is the target
right now. The stored report is never silently rewritten — which is why it can
be hash-chained in the first place.

## Trying the button in a browser

```bash
ENIGMA_API_TOKEN=secret enigma serve --port 8737 --allow-host 127.0.0.1
```

Then `POST /verify` with the same assessment and findings, and open
`http://127.0.0.1:8737/report/ASM-LIVE-DEMO`. Each finding card carries a
▶ *Prove it live* button, which `POST`s to `/prove`. Saving that page to disk
keeps the layout but not the button — it needs the running server.

## Safety

The target is created by the demo itself, on loopback, and is torn down when it
finishes. Every probe still passes the authorization gate; point the demo at
anything you are not authorized to assess and it returns `ASSESSMENT BLOCKED`
without sending a request.
