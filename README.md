# Enigma

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

**Runnable MCP demo** — a simulated OpenClaw agent verifies findings against a
real local target over MCP (no install, no external network):

```bash
python examples/mcp/openclaw_agent_demo.py
```

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
| `INCONCLUSIVE` | Data/conditions were insufficient (blocked, skipped, error, or inconsistent). |

### Built-in safe verification procedures

| `check` | What it observes (non-destructive) |
|---|---|
| `security_header` | Whether a security header (e.g. `Content-Security-Policy`) is present/absent. |
| `reflection` | Whether a benign random marker sent as a query value is reflected verbatim. |
| `http_method` | Whether a method is advertised in the `Allow` header (via `OPTIONS`). |

A finding whose `check` is unknown or unsupported is **skipped** to
`INCONCLUSIVE` rather than probed unsafely.

---

## Assessment profiles

| Profile | Methods | Probes/finding | State-changing |
|---|---|---|---|
| `passive` | GET, HEAD | 1 | never |
| `safe_verification` *(default)* | GET, HEAD, OPTIONS | 5 | never |
| `authorized` | GET, HEAD, OPTIONS | 10 | never |

---

## Repository layout

```
src/enigma/
  core/           assessment, target, scope, authorization, configuration
  authorization/  scope guard, policy guard, authorization-first validator
  agent/          OpenClaw adapter (integration seam)
  findings/       finding schema, confidence, normalizer
  verification/   engine, safe procedures, HTTP transport, reproducibility
  evidence/       collector, sanitizer, store
  methodologies/  OSSTMM taxonomy, controls, mapper
  reporting/      json, markdown, html (report + dashboard), summary/metrics
  service.py      transport-agnostic facade shared by every surface
  integrations/   REST + webhook API + HTML dashboard, MCP server, client SDK
  controller.py   end-to-end orchestration
  cli.py          `enigma validate` / `verify` / `serve` / `mcp`
tests/            unit + integration (local HTTP server, REST API, MCP e2e) — 79 tests
examples/         assessment / findings / verification-result JSON
docs/             architecture, authorization, verification, evidence, osstmm...
```

---

## Tests

```bash
python3 -m pytest          # 79 tests, no external network required
```

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
