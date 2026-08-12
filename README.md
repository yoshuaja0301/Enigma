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
sanitized evidence:

```bash
enigma verify \
  --assessment examples/assessment.json \
  --findings   examples/findings.json \
  --format json --evidence-dir ./evidence
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

## Pipeline

```
OpenClaw findings
   → normalize            (findings/normalizer.py)
   → authorization gate   (authorization/validator.py: authorization → scope → policy)
   → verification         (verification/engine.py + safe procedures)
   → reproducibility      (verification/reproducibility.py)
   → evidence (sanitized) (evidence/*)
   → OSSTMM mapping       (methodologies/osstmm/*)
   → report / summary     (reporting/*)
```

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
  reporting/      json, markdown, summary/metrics
  controller.py   end-to-end orchestration
  cli.py          `enigma validate` / `enigma verify`
tests/            unit + integration (local HTTP server) — 51 tests
examples/         assessment / findings / verification-result JSON
docs/             architecture, authorization, verification, evidence, osstmm...
```

---

## Tests

```bash
python3 -m pytest          # 51 tests, no network required
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
