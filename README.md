# Enigma

[![CI](https://github.com/yoshuaja0301/Enigma/actions/workflows/ci.yml/badge.svg)](https://github.com/yoshuaja0301/Enigma/actions/workflows/ci.yml)

**Evidence-based verification framework for AI-assisted, authorized web vulnerability assessment.**

Enigma is a *proof layer* for AI-assisted web security assessment. An AI agent
(**OpenClaw**) proposes *potential* findings; Enigma decides whether those
findings can actually be **proven** — under explicit authorization, within a
declared scope, using controlled and non-destructive probes, with sanitized
evidence and a reproducibility check — and maps the outcome to the **OSSTMM**
methodology.

> Enigma is not a vulnerability scanner. It answers one question:
> *"OpenClaw found an indication of a vulnerability — can that indication be
> proven through an authorized, controlled, reproducible assessment with
> defensible evidence?"*

Enigma is **target-agnostic**: targets are supplied as configuration. SIPONGI is
treated as one *case study / evaluation target*, never as a special case baked
into the engine.

---

## Core principles

1. **Authorization-first** — every probe passes through a fixed gate
   (`authorization → scope → policy`) before anything is sent. An out-of-scope or
   unauthorized target yields `ASSESSMENT BLOCKED` and **no request is made**.
2. **AI finds, Enigma verifies** — the agent's confidence is a *hypothesis*,
   never proof. Enigma runs its own controlled verification and issues the
   verdict.
3. **Evidence-based** — every verified finding carries sanitized, reviewable
   technical evidence. Credentials, tokens, session material and obvious PII are
   redacted before storage.
4. **Safe by default** — the recommended `safe_verification` profile only sends
   read-oriented, non-destructive probes (no state-changing methods, bounded
   probe counts). The verification procedures are observational, not weaponized.

---

## Install

```bash
pip install -e .            # from a clone
# dev extras (pytest):
pip install -e ".[dev]"
```

Runtime dependencies: **none** (standard library only). Python ≥ 3.9.

---

## Quick start (CLI)

Validate authorization/scope/policy only — sends no probes:

```bash
enigma validate --assessment examples/assessment.json
```

Verify a batch of findings and print a report. Use `--offline` to run the whole
pipeline with a fake transport (no network) for a demo/dry run:

```bash
enigma verify \
  --assessment examples/assessment.json \
  --findings   examples/findings.json \
  --format md --offline
```

Against a real, authorized target, drop `--offline` and (optionally) persist
sanitized evidence. Reports render as `md`, `json`, or a self-contained
**`html`** page (theme-aware, no dependencies) — write it to a file with
`--output`:

```bash
enigma verify \
  --assessment examples/assessment.json \
  --findings   examples/findings.json \
  --format html --output report.html --evidence-dir ./evidence
```

---

## Quick start (library)

```python
from enigma import AssessmentController, StaticOpenClawAdapter, load_assessment
from enigma.reporting import to_markdown

assessment = load_assessment("examples/assessment.json")
adapter = StaticOpenClawAdapter.from_file("examples/findings.json")

controller = AssessmentController(evidence_dir="./evidence")
results = controller.run(assessment, adapter)
print(to_markdown(results))
```

Each result is a `CONFIRMED` / `NOT_CONFIRMED` / `INCONCLUSIVE` verdict with a
reproducibility flag, sanitized evidence id and an OSSTMM mapping.

---

## Connecting OpenClaw

OpenClaw can connect through whatever surface fits its stack — all of them wrap
the same `EnigmaService` facade, so the JSON contract is identical, and the
authorization-first gate always applies.

| Surface | How | Best for |
|---|---|---|
| **In-process adapter** | implement `OpenClawAdapter.get_findings` | same pipeline/process |
| **REST + webhook API** | `enigma serve` → `POST /verify`, `/webhook/openclaw`, `GET /results/{id}`, plus an HTML **dashboard** at `/` and `/report/{id}` | any HTTP client; async push via `callback_url`; browser dashboard |
| **MCP server** | `enigma mcp` (JSON-RPC over stdio; tools `validate_scope`, `verify_findings`, `get_result`) | AI agents that speak MCP |
| **Client SDK** | `enigma.integrations.client.EnigmaClient` | Python consumers of the REST API |

```bash
enigma serve --port 8737 --token SECRET --allow-host authorized-target.example
enigma mcp   --allow-host authorized-target.example      # for an AI agent
```

**Runnable demos** — no install, no API key, no external network. Each starts a
throwaway local target and verifies against it:

```bash
python examples/live-demo/five_finders_demo.py   # all five finders + prove-it-live
python examples/mcp/openclaw_agent_demo.py       # OpenClaw → Enigma over MCP
python examples/openclaw/custom_adapter_demo.py  # LLM-style adapter end to end
```

The [live demo](examples/live-demo/) is the one to run first: it feeds Enigma the
output of OpenClaw, Nuclei, ZAP, Nmap and WhatWeb at once, shows a *High
confidence* scanner alert being refuted by the server and a 0.30 one confirmed,
catches a forged report via the manifest, then **fixes the target mid-run** and
re-proves the same finding — watching the verdict flip while the stored record
stays put.

Safety for exposed deployments: set a bearer token (`--token` / `ENIGMA_API_TOKEN`)
and a server-side host allowlist (`--allow-host`) so an endpoint can't be turned
into a general-purpose scanner. See [`docs/integration.md`](docs/integration.md).

## Pipeline

```
Assessment                     core/           target + authorization + scope + profile
   ↓
Authorization / Scope / Policy authorization/  authorization → scope → policy   (gate)
   ↓
OpenClaw Finding               agent/          AI proposes a POTENTIAL finding
   ↓
Finding Normalizer             findings/       raw proposal → consistent Finding schema
   ↓
Verification Engine            verification/   controlled safe probes + reproducibility
   ↓                                           (the gate is re-checked before every probe)
Evidence                       evidence/       sanitized, reviewable artifacts
   ↓
OSSTMM Mapping                 methodologies/  channel / section / operational controls
   ↓
Verdict + Report               reporting/      CONFIRMED / NOT_CONFIRMED / INCONCLUSIVE
```

The gate is established from the **Assessment** up front and enforced *inside*
the Verification Engine on every probe — so a finding can never cause a request
outside its authorized scope.

### Verdict model

| Verdict | Meaning |
|---|---|
| `CONFIRMED` | Required evidence was obtained and the finding reproduces per procedure. |
| `NOT_CONFIRMED` | The hypothesis could not be proven with the available verification. |
| `INCONCLUSIVE` | Data/conditions were insufficient (blocked, reported, error, or inconsistent). |

### Proof — showing it's real, not an AI guess

Every finding carries a **human-readable receipt**: what it means and why it
matters in plain language (English or Indonesian), the *exact* request Enigma
sent and the server's *exact* reply, and the single decisive line that proves
it. And it can be **re-proven live**:

```bash
enigma prove --assessment a.json --findings f.json --id F-1 --lang id
```

The whole report renders in either language — `enigma verify --lang id` for the
Markdown/HTML report, and `?lang=id` on the served page. JSON stays English: it
is the machine contract, and reports stored in different languages could not be
compared. OSSTMM's own vocabulary (channels, controls, the 17 module names, RAV
grades) is never translated, so a reader can always trace a finding back to the
methodology.

The report served at `GET /report/{id}` adds a **▶ Prove it live** button per
finding (`POST /prove`) that re-runs the check against the real target on demand
and shows the fresh evidence. See [`docs/proof.md`](docs/proof.md).

### Feeding in scanner output (Nuclei · ZAP · Nmap · WhatWeb)

Scanners are finders too — their output is parsed into findings and **verified**,
not trusted:

```bash
enigma verify --assessment a.json \
  --nuclei nuclei.jsonl --zap zap-report.json \
  --nmap scan.xml --whatweb whatweb.json
```

Findings matching one of the nine checks are verified automatically; the rest
stay `reported`. The tool's own severity becomes the finding's `confidence` — the
hypothesis slot verification never reads — so a *High confidence* ZAP alert can
still come back `NOT_CONFIRMED` when the server disagrees, and a Nuclei *info*
finding can come back `CONFIRMED`. See [`docs/tool-parsers.md`](docs/tool-parsers.md).

### OSSTMM methodology coverage — the module checklist

Enigma encodes the four OSSTMM 3 test phases and their **17 modules**, and maps
each testing instrument to the modules it exercises:

| Instrument | Modules | Phase |
|---|---|---|
| Nmap | 4 Visibility Audit, 5 Access Verification | B |
| WhatWeb | 9 Configuration, 12 Exposure Verification | C |
| Nuclei | 12 Exposure Verification | C |
| OWASP ZAP | 7 Controls, 12 Exposure Verification | B, C |
| Enigma | 1 Posture Review (the authorization gate) + whatever its checks exercise | A, B, C |

Declare them per assessment (`"instruments": ["nmap", "whatweb", ...]`) and every
report gains a per-phase checklist **with attribution** — which instrument or
check covered each module, and which modules remain uncovered (Phase D is not
reachable non-intrusively, and is reported as such). Instruments record
*methodological* coverage only: anything they find still passes through Enigma's
verification before it can move a verdict or the RAV. See
[`docs/osstmm-modules.md`](docs/osstmm-modules.md).

### Per-source metrics — which finder's claims survive proof

Enigma accepts findings from OpenClaw *and* from Nmap, WhatWeb, Nuclei and ZAP.
Every report breaks the outcome down per finder (`summary.by_source`, a table in
Markdown and HTML), so "how much of this source's output survived verification?"
is a number rather than an impression:

```
| Source   | Findings | Confirmed | Not confirmed | Undecided | Confirmation rate | Avg. claimed conf. |
|----------|----------|-----------|---------------|-----------|-------------------|--------------------|
| zap      |        1 |         0 |             1 |         0 |                0% |               0.85 |
| nuclei   |        1 |         1 |             0 |         0 |              100% |               0.30 |
```

Rates divide by **decided** findings (confirmed + not confirmed), never by the
total: a finding Enigma could not judge is Enigma's limit, not the finder's
error, so it is published as `undecided` instead of counted as a miss. See
[`docs/metrics.md`](docs/metrics.md).

### Run manifest — the report is checkable, not just readable

Every report carries a `manifest`: the run's version, target, profile and UTC
timestamp, the digest of the `summary`, plus one hash-chained entry per finding
holding the digest of that finding **as published** (proof receipt included) and
of its sanitized evidence.

```python
from enigma.evidence import verify_report
verify_report(report)                  # [] when intact
verify_report(report, evidence)        # also re-hash the stored artifacts
```

Rewrite a verdict, doctor a proof receipt, edit a metric, append a fabricated
finding, reorder or drop an entry, or alter a stored evidence file — each comes
back as a named problem. It proves the report and its evidence were not altered
relative to each other; it is **not** a signature, since anyone who can rewrite
the whole manifest can recompute the chain. See
[`docs/evidence.md`](docs/evidence.md).

### OSSTMM RAV — a measured security score

Beyond per-finding verdicts, Enigma computes an OSSTMM 3 **Risk Assessment
Value**: arithmetic over the balance of *porosity* (exposed surface), *controls*
(protections observed working) and *limitations* (verified flaws, weighted by
category) — not a subjective severity rating.

```
actual_security = 100 + controls_sum − opsec_sum − limitation_sum
```

Crucially it is **computed from verified observations only**: `CONFIRMED`
findings become limitations, `NOT_CONFIRMED` findings evidence a control, and
unverified findings are excluded *and counted*, so an AI's confidence can never
move the score. It appears in every report (JSON `summary.rav`, a Markdown
table, an HTML panel). See [`docs/rav.md`](docs/rav.md).

### Built-in safe verification procedures

| `check` | What it observes (non-destructive) |
|---|---|
| `security_header` | Whether a security header (e.g. `Content-Security-Policy`) is present/absent. |
| `reflection` | Whether a benign random marker sent as a query value is reflected verbatim. |
| `http_method` | Whether a method is advertised in the `Allow` header (via `OPTIONS`). |
| `cookie_flags` | Whether a `Set-Cookie` is missing a flag (`Secure` / `HttpOnly` / `SameSite`). |
| `cors` | Whether an arbitrary `Origin` is reflected in `Access-Control-Allow-Origin` (worse with credentials). |
| `tls_redirect` | Whether plain HTTP is upgraded to HTTPS (redirect observed, never followed; notes HSTS). |
| `clickjacking` | Whether the page is frameable (no `X-Frame-Options`, no CSP `frame-ancestors`). |
| `directory_listing` | Whether a server-generated directory index is exposed. |
| `server_version` | Whether server/technology versions are disclosed (`Server`, `X-Powered-By`, …). |

Discovery is **unrestricted** — OpenClaw may report any vulnerability type. A
finding that matches one of these checks is verified automatically; anything
else is kept with status `reported` (never dropped, never probed unsafely) for a
reviewer to pick up.

---

## Assessment profiles

| Profile | Methods | Probes/finding | State-changing |
|---|---|---|---|
| `passive` | GET, HEAD | 1 | never |
| `safe_verification` *(default)* | GET, HEAD, OPTIONS | 5 | never |
| `authorized` | GET, HEAD, OPTIONS | 10 | never |

---

## Repository layout

**Core foundation** — one package per pipeline stage, in pipeline order:

```
src/enigma/
  core/           ①  assessment, target, scope, authorization, configuration
  authorization/  ②  scope guard, policy guard, authorization-first validator
  agent/          ③  OpenClaw adapters (static · callable/LLM · HTTP)
  findings/       ④  finding schema, confidence, normalizer
  verification/   ⑤  engine, safe procedures, HTTP transport, reproducibility
  evidence/       ⑥  collector, sanitizer, store
  methodologies/  ⑦  OSSTMM taxonomy, controls, mapper
  reporting/      ⑧  verdict rendering: json, markdown, html, summary metrics
  controller.py      end-to-end pipeline orchestration
  explain.py         plain-language explanations + human-readable proof receipts
  cli.py             `enigma validate` / `verify` / `prove`
```

**Optional extensions** — built on top of the same pipeline; remove them and the
core still works:

```
  service.py      transport-agnostic facade shared by every surface
  integrations/   REST + webhook API + HTML dashboard, MCP server, client SDKs
  cli.py          `enigma serve` / `enigma mcp` subcommands
  reporting/html  HTML report + dashboard rendering
```

**Supporting:**

```
tests/            unit + integration (local HTTP server, REST API, MCP e2e) — 303 tests
  fixtures/       raw OpenClaw payloads used by the normalizer tests
examples/         assessment / findings / verification-result JSON
  live-demo/      five finders vs one live target, manifest + prove-it-live (start here)
  mcp/ openclaw/  MCP and custom-adapter demos
docs/             architecture, authorization, assessment-model, verification, ...
.github/          CI: full suite on Python 3.9–3.13 + CLI/demo smoke tests
```

---

## Tests

```bash
python3 -m pytest          # 303 tests, no external network required
```

CI (GitHub Actions) runs the full suite on Python 3.9–3.13 on every push and
pull request, plus a smoke job that asserts the CLI end to end — including that
an out-of-scope target really exits with `ASSESSMENT BLOCKED` — and runs the MCP
and adapter demos. See [`.github/workflows/ci.yml`](.github/workflows/ci.yml).

The integration suite spins up a throwaway local HTTP server on `127.0.0.1` and
runs the full pipeline against it (authorized, in scope).

---

## Safety & scope

- Assess only targets with clear authorization; scope must be set before start.
- Verification follows the assessment profile and policy; the default is minimal
  and controlled.
- Evidence is sanitized and never stores credentials, tokens, secrets or
  unnecessary personal data.
- Verification is **not** intended for weaponization or out-of-scope exploitation.

See [`docs/`](docs/) for details.

## License

MIT — see [LICENSE](LICENSE).
