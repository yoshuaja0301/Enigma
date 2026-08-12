# OpenClaw integration

OpenClaw is the AI assessor. It *proposes* potential findings; Enigma consumes
them through a small adapter interface and does everything else (authorization,
verification, evidence, verdict).

## The interface

```python
from typing import Any, Dict, List
from enigma.core.assessment import Assessment

class OpenClawAdapter(Protocol):
    def get_findings(self, assessment: Assessment) -> List[Dict[str, Any]]:
        ...
```

Any real integration (HTTP call to an OpenClaw service, a local model, a message
queue) just implements `get_findings`. Enigma depends only on this interface, so
the concrete transport is out of scope for the framework.

## Adapters

A real integration is usually just picking one adapter and wiring your model or
endpoint. All return raw finding dicts; nothing else in the pipeline changes.

### Static (replay / tests / offline eval)

```python
from enigma.agent.openclaw import StaticOpenClawAdapter

adapter = StaticOpenClawAdapter.from_file("examples/findings.json")
adapter = StaticOpenClawAdapter.from_data([{ "finding_id": "F-1", ... }])
```

The findings source may be a bare list or an object with a `findings` array.

### LLM / any function (`CallableOpenClawAdapter`)

The realistic "AI agent" case, and provider-agnostic — you pass a completion
function `(prompt) -> text`. Enigma builds the prompt (target + supported checks)
and parses the model's JSON output, tolerating a surrounding code fence.

```python
from enigma.agent.openclaw import CallableOpenClawAdapter

def complete(prompt: str) -> str:
    return anthropic_client.messages.create(
        model="claude-...", max_tokens=2000,
        messages=[{"role": "user", "content": prompt}],
    ).content[0].text

adapter = CallableOpenClawAdapter(complete)
```

Runnable demo (uses a stub model, no API key needed):
`python examples/openclaw/custom_adapter_demo.py`.

### HTTP service (`HttpOpenClawAdapter`)

If OpenClaw is a service: Enigma POSTs a JSON description of the target
(`build_openclaw_request`) and expects a findings array (bare or
`{"findings": [...]}`).

```python
from enigma.agent.openclaw import HttpOpenClawAdapter

adapter = HttpOpenClawAdapter("https://openclaw.example/assess", api_key="...")
```

### Your own

Implement `get_findings(assessment) -> list[dict]` any way you like
(message queue, MCP client, subprocess). Enigma normalizes, gates, verifies.

## What Enigma tells OpenClaw

To keep proposals verifiable, Enigma advertises the **supported checks** and the
finding schema (via `build_openclaw_request` / `build_openclaw_prompt`), and
parses whatever comes back (`parse_openclaw_findings`). Authorization/scope are
never shared as something OpenClaw can decide — only the target description is.

## Raw finding shape

```json
{
  "finding_id": "F-00017",
  "type": "potential_vulnerability",
  "category": "missing_security_header",
  "title": "Content-Security-Policy header appears to be missing",
  "confidence": 0.76,
  "target": { "host": "authorized-target.example", "path": "/search" },
  "check": "security_header",
  "parameters": { "header": "Content-Security-Policy" }
}
```

The `FindingNormalizer` fills gaps and infers a safe `check` from the `category`
when one isn't given. If it can't map the finding to a known, safe verification
procedure, `check` becomes `None` and the finding is verified as
`INCONCLUSIVE` (skipped) rather than probed unsafely.

## What OpenClaw cannot do

- It cannot decide whether a target is in scope or authorized.
- It cannot mark a finding `CONFIRMED`.
- Its `confidence` is recorded as `ai_confidence` for research comparison, but it
  never substitutes for verification.
