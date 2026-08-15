# Verification

The verification engine tries to **prove or disprove** a normalized finding
using controlled, non-destructive probes, then issues a verdict.

## Flow (`VerificationEngine.verify`)

1. **Pre-flight gate** — authorize a GET on the finding URL. If blocked at
   authorization/scope, return a `blocked` result immediately (nothing sent).
2. **Select procedure** — from the finding's `check`. Unknown/missing or
   under-specified → `skipped` (`INCONCLUSIVE`).
3. **Probe** — run the procedure `repeat_count` times (bounded by the policy's
   `max_probes_per_finding`). Every request goes through `ProbeContext.send`,
   which re-checks the authorization gate per request.
4. **Reproducibility** — assess whether the observed condition was consistent
   across probes.
5. **Verdict + evidence** — derive the verdict, collect sanitized evidence.

## Built-in safe procedures

| `check` | Method(s) | Condition tested (weakness) | Key parameters |
|---|---|---|---|
| `security_header` | GET | required header absent | `header` |
| `reflection` | GET | benign marker reflected verbatim | `param` |
| `http_method` | OPTIONS | method advertised in `Allow` | `method` |
| `cookie_flags` | GET | `Set-Cookie` missing a flag | `flag` (`Secure`/`HttpOnly`/`SameSite`), optional `cookie` |
| `cors` | GET + `Origin` header | arbitrary `Origin` reflected (or `*`) in `Access-Control-Allow-Origin` | optional `origin` |
| `tls_redirect` | GET (http:// variant) | HTTP not upgraded to HTTPS | — |
| `clickjacking` | GET | page is frameable (no `X-Frame-Options`, no CSP `frame-ancestors`) | — |
| `directory_listing` | GET | a server-generated directory index is exposed | — |
| `server_version` | GET | server/technology version disclosed in headers | — |

All procedures are strictly observational, non-destructive, and read-oriented:

- `reflection` sends only an alphanumeric marker (`enigma<random>`), never an
  HTML/script payload — it detects *reflection*, not exploitability.
- `cors` sends a benign probe `Origin` header on a GET and reads the response;
  it flags the dangerous case of a reflected origin **with** credentials.
- `tls_redirect` requests the `http://` variant of the target path (still through
  the authorization gate) and *observes* the redirect — it never follows it —
  and also notes whether `Strict-Transport-Security` (HSTS) is present.

Every request a procedure makes still passes through the authorization-first
gate via `ProbeContext.send`, including the `tls_redirect` probe's `http://` URL.

## Verdict logic

Let `results` be the per-probe booleans (condition met) from successful probes.

| Situation | Verdict | Reproducible |
|---|---|---|
| all `True` | `CONFIRMED` | yes |
| all `False` | `NOT_CONFIRMED` | yes |
| mixed | `INCONCLUSIVE` | no |
| no successful probes (all errored) | `INCONCLUSIVE` (`status=error`) | no |
| blocked by gate | `INCONCLUSIVE` (`status=blocked`) | no |
| no safe procedure | `INCONCLUSIVE` (`status=skipped`) | no |

Verification confidence is Enigma's own, derived from the verdict and the
reproducibility ratio — it is independent of the AI's `confidence`.

## Result shape

See [`examples/verification-result.json`](../examples/verification-result.json)
for the full `to_dict()` output, including `target`, `finding`,
`verification.observations`, `evidence.evidence_id` and `methodology`.
