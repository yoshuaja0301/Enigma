# Architecture

Enigma separates *finding generation* (done by an AI agent, OpenClaw) from
*proof* (done by Enigma). The engine is target-agnostic — a target is just
configuration.

```
USER (target + authorization + scope + profile)
        │
        ▼
AssessmentController
        │
        ├── FindingNormalizer          normalize raw OpenClaw findings
        │
        ▼
VerificationEngine
        │  ┌───────────────────────────────────────────┐
        │  │ AuthorizationValidator (authorization-first)│
        │  │   authorization → scope → policy            │
        │  └───────────────────────────────────────────┘
        │        │ blocked → ASSESSMENT BLOCKED (nothing sent)
        │        ▼ allowed
        │  Safe probe procedures (via ProbeContext)
        │        ▼
        │  ReproducibilityEngine   (repeat probes, check consistency)
        │        ▼
        │  EvidenceCollector + Sanitizer + Store
        │
        ▼
OsstmmMapper  →  Reporting (JSON / Markdown / Summary)
        │
        ▼
Final finding: CONFIRMED / NOT_CONFIRMED / INCONCLUSIVE
```

## Module map

| Package | Responsibility |
|---|---|
| `core` | Assessment, Target, Scope, Authorization, configuration loading. |
| `authorization` | Scope guard, policy guard, and the authorization-first validator. |
| `agent` | The `OpenClawAdapter` interface + a static (file/list) adapter. |
| `findings` | Normalized `Finding`, `Verdict`, confidence helpers, normalizer. |
| `verification` | Engine, safe procedures, HTTP transport, reproducibility. |
| `evidence` | Collector, sanitizer, store. |
| `methodologies/osstmm` | Taxonomy, operational controls, mapper. |
| `reporting` | JSON / Markdown reporters and summary metrics. |
| `controller` | End-to-end orchestration. |
| `cli` | `enigma validate` / `enigma verify`. |

## Key design property

The only path to the network is `ProbeContext.send`, and it calls the
`AuthorizationValidator` *before* the transport. A verification procedure
therefore **cannot** issue an out-of-scope or disallowed request even by
mistake — the gate is not optional and not bypassable by the finding source.
