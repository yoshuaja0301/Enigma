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

## Static adapter (replay / tests / offline eval)

```python
from enigma.agent.openclaw import StaticOpenClawAdapter

adapter = StaticOpenClawAdapter.from_file("examples/findings.json")
# or
adapter = StaticOpenClawAdapter.from_data([{ "finding_id": "F-1", ... }])
```

The findings source may be a bare list or an object with a `findings` array.

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
