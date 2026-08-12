# Assessment model

The **Assessment** is the first stage of the pipeline (see
[architecture.md](architecture.md)) — the input a user gives Enigma. It carries
everything the authorization gate and verification engine need: *what* is being
assessed, *under what authorization*, *within what scope*, and *how aggressively*.
It is validated by construction (`Assessment.from_dict`), so a malformed
assessment fails fast, before any finding is processed.

```json
{
  "assessment_id": "ASM-00001",
  "target": { "url": "https://authorized-target.example" },
  "authorization": {
    "status": "authorized",
    "reference": "ROE-2026-0007",
    "authorized_by": "target-owner"
  },
  "scope": {
    "allowed_hosts": ["authorized-target.example"],
    "excluded_paths": ["/logout", "/account/delete"],
    "allowed_ports": []
  },
  "profile": "safe_verification",
  "methodology": "OSSTMM"
}
```

| Field | Description |
|---|---|
| `assessment_id` | Unique identifier for the assessment. |
| `target.url` | Absolute URL (scheme + host required). |
| `authorization.status` | Must be `authorized` for any probe to run. |
| `scope.allowed_hosts` | Hosts permitted for probing. |
| `scope.excluded_paths` | Paths that must never be touched. |
| `scope.allowed_ports` | Optional port allow-list. |
| `profile` | `passive` \| `safe_verification` \| `authorized`. |
| `methodology` | Methodology label (currently `OSSTMM`). |

## Enumerated values

| Enum | Values | Notes |
|---|---|---|
| `authorization.status` | `authorized`, `unauthorized`, `unknown` | Only `authorized` lets a probe run; anything else blocks at the authorization stage. |
| `profile` | `passive`, `safe_verification`, `authorized` | Drives the policy (allowed methods, probe budget). Default is `safe_verification`. |

## Validation rules

`Assessment.from_dict` enforces the foundation up front:

- `assessment_id` and `target` are **required** (missing → `ValueError`).
- `target.url` must be absolute (scheme **and** host) — a bare host is rejected.
- unknown `profile` → `ValueError`; unknown `authorization.status` → `unknown`
  (which is treated as *not authorized*, i.e. it blocks).
- `allowed_hosts` are lower-cased; `allowed_ports` empty means "any port".

`target` may be given as `{ "url": "..." }` or the URL string directly.

## Where it feeds

The Assessment flows straight into the gate: `authorization.status` →
authorization stage, `scope` → scope stage, `profile` → policy stage. See
[authorization.md](authorization.md).

Load one with:

```python
from enigma import load_assessment
assessment = load_assessment("examples/assessment.json")   # path, or a dict
```
