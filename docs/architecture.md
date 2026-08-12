# Architecture

Enigma separates *finding generation* (done by an AI agent, OpenClaw) from
*proof* (done by Enigma). The engine is target-agnostic — a target is just
configuration.

## The pipeline

```
Assessment
    ↓        target + authorization + scope + profile
Authorization / Scope / Policy
    ↓        authorization → scope → policy   (the gate)
OpenClaw Finding
    ↓        AI proposes a POTENTIAL finding (+ confidence)
Finding Normalizer
    ↓        raw proposal → consistent internal Finding
Verification Engine
    ↓        controlled, non-destructive probes (gate re-checked per probe)
Evidence
    ↓        sanitized, reviewable artifacts
OSSTMM Mapping
    ↓        channel / section / operational controls
Verdict
             CONFIRMED · NOT_CONFIRMED · INCONCLUSIVE   (+ report)
```

Each stage maps to exactly one package, so the code reads like the diagram:

| Stage | Module / entry point | Input → Output |
|---|---|---|
| Assessment | `core` (`load_assessment`) | config dict/file → `Assessment` |
| Authorization / Scope / Policy | `authorization` (`AuthorizationValidator`) | URL + method → allow / block(stage) |
| OpenClaw Finding | `agent` (`OpenClawAdapter`) | `Assessment` → raw finding dicts |
| Finding Normalizer | `findings` (`FindingNormalizer`) | raw dict → `Finding` |
| Verification Engine | `verification` (`VerificationEngine`) | `Finding` → probe outcomes |
| Reproducibility | `verification` (`ReproducibilityEngine`) | outcomes → consistent? |
| Evidence | `evidence` (`EvidenceCollector`/`Sanitizer`/`Store`) | exchanges → sanitized `Evidence` |
| OSSTMM Mapping | `methodologies/osstmm` (`OsstmmMapper`) | `Finding` + verdict → mapping |
| Verdict + Report | `findings.Verdict` + `reporting` | results → JSON / Markdown / HTML |

The whole pipeline is driven by `AssessmentController` (or, exposed as a service,
`EnigmaService` behind the CLI / API / MCP surfaces).

## Orchestration & surfaces

```
                 ┌──────────── surfaces ────────────┐
 OpenClaw / user │ cli · integrations(REST · webhook │
                 │        · MCP) · client SDK        │
                 └───────────────┬──────────────────┘
                                 ▼
                          EnigmaService          (service.py — facade)
                                 ▼
                       AssessmentController       (controller.py — pipeline)
                                 ▼
                   the pipeline stages shown above
```

## Module map

**Core** implements the pipeline; **extension** modules are built on top of it
and can be removed without affecting the core.

| Package / file | Kind | Responsibility |
|---|---|---|
| `core` | core | Assessment, Target, Scope, Authorization, configuration loading. |
| `authorization` | core | Scope guard, policy guard, and the authorization-first validator. |
| `agent` | core | `OpenClawAdapter` interface + static / callable(LLM) / HTTP adapters. |
| `findings` | core | Normalized `Finding`, `Verdict`, confidence helpers, normalizer. |
| `verification` | core | Engine, safe procedures, HTTP transport, reproducibility. |
| `evidence` | core | Collector, sanitizer, store. |
| `methodologies/osstmm` | core | Taxonomy, operational controls, mapper. |
| `reporting` | core | JSON / Markdown / summary metrics (HTML renderer is an extension). |
| `controller.py` | core | End-to-end pipeline orchestration. |
| `cli.py` / `__main__.py` | core | `enigma validate` / `verify` (plus `serve` / `mcp`). |
| `service.py` | extension | Transport-agnostic facade shared by every surface. |
| `integrations` | extension | REST + webhook API + HTML dashboard, MCP server, client SDKs. |
| `reporting/html.py` | extension | HTML report + dashboard rendering. |

## Key design property

The only path to the network is `ProbeContext.send`, and it calls the
`AuthorizationValidator` *before* the transport. A verification procedure
therefore **cannot** issue an out-of-scope or disallowed request even by
mistake — the gate is not optional and not bypassable by the finding source.
