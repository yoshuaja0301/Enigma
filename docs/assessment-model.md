# Assessment model

An assessment is the input a user gives Enigma. It is validated by construction
(`Assessment.from_dict`).

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

Load one with:

```python
from enigma import load_assessment
assessment = load_assessment("examples/assessment.json")
```
