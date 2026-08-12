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

| `check` | Method(s) | Condition tested | Nature |
|---|---|---|---|
| `security_header` | GET | required header absent | observational |
| `reflection` | GET | benign marker reflected verbatim | observational |
| `http_method` | OPTIONS | method advertised in `Allow` | observational |

The `reflection` procedure sends only an alphanumeric marker
(`enigma<random>`), never an HTML/script payload — it detects *reflection*, not
exploitability.

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
