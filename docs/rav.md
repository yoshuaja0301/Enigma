# RAV — Risk Assessment Value (OSSTMM 3)

Enigma reports an OSSTMM **RAV** alongside its verdicts. Where a verdict answers
*"is this one finding real?"*, the RAV answers *"given everything we verified,
how secure is this target?"* — as a reproducible number rather than an opinion.

## Why the RAV, and not a severity score

CVSS-style scores encode expert judgement about how bad a flaw *could* be. The
RAV instead measures the **balance** between three counted quantities: what is
exposed, what protects it, and what is broken. That property is what makes it
appropriate for Enigma's research question:

- it is **arithmetic over facts**, so two people scoring the same evidence get
  the same number;
- it therefore cannot be inflated by an AI's confidence — and in Enigma it
  literally cannot, because only *verified* observations reach it.

## Inputs

Per OSSTMM 3, Chapter 3 (*Operational Security Metrics*):

| Input | Meaning | Enigma's source |
|---|---|---|
| **OpSec (Porosity)** | the attack surface actually exposed: `Visibility + Access + Trust` | distinct paths probed; interaction points (`http_method`, `cors`); trust points (`cors`, `reflection`) |
| **Controls** | the ten operational controls, Class A (interactive) + Class B (process) | credited where verification *observed the control working* (a `NOT_CONFIRMED` check) |
| **Limitations** | verified flaws, weighted by category | `CONFIRMED` findings only |

### Limitation categories and weights

| Category | Weight | Meaning | Example check |
|---|---|---|---|
| Vulnerability | 5.0 | flaw granting access or trust | `cors`, `http_method` |
| Weakness | 4.0 | a control that fails | `security_header`, `cookie_flags`, `tls_redirect`, `clickjacking` |
| Concern | 3.0 | insufficient assurance/logging | `reflection` |
| Exposure | 2.0 | information disclosure | `directory_listing`, `server_version` |
| Anomaly | 1.0 | unidentifiable behaviour | *(fallback)* |

Limitations are weighted **relative to porosity**: the same flaw counts for
proportionally more on a small surface than on a large one.

## Calculation

Each quantity is reduced to a base-10 logarithmic magnitude,
`10 · log₁₀(1 + x)`, then combined:

```
actual_security = 100 + controls_sum − opsec_sum − limitation_sum
```

Also reported:

- **True Protection** — how much of the porosity the evidenced controls cover.
- **True Coverage** — the share of the ten controls in place.
- **Security deficit** — how far below perfect balance the target sits.

### How to read the number

**100 % means perfect balance, not "no findings."** A target with *zero* flaws
still scores slightly below 100 % if only some controls are evidenced — the RAV
is measuring balance, not the absence of findings.

The model is internally consistent on this point: `controls_sum` equals
`opsec_sum` exactly when ten controls are evidenced per porosity point, which is
OSSTMM's balance condition. (`tests/unit/test_rav.py` asserts this.)

Grades are a reporting convenience, **not part of OSSTMM**:

| Actual Security | Grade |
|---|---|
| ≥ 100 % | balanced |
| ≥ 90 % | adequate |
| ≥ 75 % | degraded |
| ≥ 50 % | poor |
| < 50 % | critical |

## Verified-only rule

This is the rule that ties the RAV to Enigma's core claim:

| Verdict | Effect on the RAV |
|---|---|
| `CONFIRMED` | becomes a **Limitation** (weighted by category) |
| `NOT_CONFIRMED` | **evidences a control** (the protection was observed working) |
| `INCONCLUSIVE` / `reported` | **excluded**, but counted in `excluded_unverified` |

So an unproven hypothesis can never move the security metric, and the report
always states how many findings the score does *not* rest on — the coverage is
visible rather than implied.

## Example

```
Actual Security : 79.4%  (degraded)
Security deficit: 20.6%
True Protection : 9.37%   True Coverage: 20.0%
Porosity        : 6 (vis 5, acc 1, trust 0)
Controls        : 2/10 → ['Integrity', 'Authentication']
Limitations     : {'weakness': 3, 'exposure': 2}  (total 5)
Excluded        : 1 (unverified)
Formula         : actual_security = 100 + controls_sum - opsec_sum - limitation_sum
                  opsec=8.451  controls=0.792  limitations=12.937
```

Every term above is reproducible from the stored evidence.

## Usage

```python
from enigma.methodologies.osstmm import compute_rav

rav = compute_rav(results)
print(rav.actual_security, rav.grade())
print(rav.to_dict())          # fully auditable breakdown
```

The RAV is also embedded in every report: `summary.rav` in JSON, an
*OSSTMM RAV* table in Markdown, and a panel in the HTML report.

## Research use

Because the RAV is derived only from verified observations, it supports the
questions Enigma's research asks:

- Does an AI-assisted assessment move the RAV **differently** from the raw count
  of AI findings? (i.e. how much of the AI's output survives proof.)
- How large is `excluded_unverified` — how much of the picture still needs a
  human?
- Do repeated assessments reproduce the same RAV? (determinism)

## Reference

ISECOM, *OSSTMM 3: The Open Source Security Testing Methodology Manual* —
Chapter 3 (Operational Security Metrics) and Appendix A (RAV calculation).

Enigma implements a faithful but **pragmatic subset**: the porosity/controls/
limitations structure and the logarithmic combination, scoped to what a safe,
authorized web assessment can actually observe. It is a mapping aid for
research, not a claim of OSSTMM certification.
