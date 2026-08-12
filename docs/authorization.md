# Authorization, scope and policy

Authorization is enforced **before** any assessment activity. The order is fixed:

```
authorization  →  scope  →  policy
```

If any stage denies, the request is blocked and nothing is sent.

## 1. Authorization

`Authorization.status` must be exactly `authorized`. Anything else
(`unknown`, `unauthorized`) blocks at the authorization stage. OpenClaw can
never set or bypass this — it only proposes findings.

## 2. Scope (`ScopeGuard`)

A URL is in scope when:

- its host is in `allowed_hosts` (case-insensitive), and
- its port is in `allowed_ports` (when specified), and
- its path does **not** match any `excluded_paths`.

Excluded-path matching is exact or prefix-with-boundary: `/logout` excludes
`/logout` and `/logout/...` but **not** `/logout-help`.

## 3. Policy (`PolicyGuard`)

Policies are derived from the assessment profile and constrain *how* Enigma may
probe:

| Profile | allowed methods | max probes/finding | state-changing |
|---|---|---|---|
| `passive` | GET, HEAD | 1 | never |
| `safe_verification` | GET, HEAD, OPTIONS | 5 | never |
| `authorized` | GET, HEAD, OPTIONS | 10 | never |

State-changing methods (`POST`, `PUT`, `PATCH`, `DELETE`) are never permitted by
the default profiles.

## Result

`AuthorizationValidator.authorize(url, method)` returns an `AuthorizationResult`
with `allowed`, the `stage` that blocked (`authorization` / `scope` / `policy`),
and a human-readable `reason`. A blocked assessment is surfaced as
`ASSESSMENT BLOCKED` and produces an `INCONCLUSIVE`, `blocked=True` result.
