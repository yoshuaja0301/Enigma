# OSSTMM test phases, modules, and instrument mapping

Where [rav.md](rav.md) answers *"how secure is the target"*, this answers
*"was the methodology actually followed"* — the checklist question.

Enigma encodes the four OSSTMM 3 **test phases** and their **17 modules**, maps
each **testing instrument** to the modules it exercises, and reports coverage
per phase **with attribution** — so a reader sees *what* covered a module rather
than taking the claim on faith.

## The four phases and 17 modules

| Phase | Name | Modules |
|---|---|---|
| **A** | Induction | 1 Posture Review · 2 Logistics · 3 Active Detection Verification |
| **B** | Interaction | 4 Visibility Audit · 5 Access Verification · 6 Trust Verification · 7 Controls Verification |
| **C** | Inquest | 8 Process Verification · 9 Configuration Verification · 10 Property Validation · 11 Segregation Review · 12 Exposure Verification · 13 Competitive Intelligence Scouting |
| **D** | Intervention | 14 Quarantine Verification · 15 Privileges Audit · 16 Survivability Validation · 17 Alert and Log Review |

## Instrument → module mapping

| Instrument | Role | Modules | Phase |
|---|---|---|---|
| **Nmap** | Port and service scanning | 4 Visibility Audit, 5 Access Verification | B |
| **WhatWeb** | Web technology identification | 9 Configuration Verification, 12 Exposure Verification | C |
| **Nuclei** | Template-based vulnerability scanning | 12 Exposure Verification | C |
| **OWASP ZAP** | Web application security scanning | 7 Controls Verification, 12 Exposure Verification | B, C |
| **Enigma** | Authorization/scope definition + evidence-based verification | 1 Posture Review (+ whatever its checks exercise) | A (+B, C) |

Enigma's own verification checks contribute coverage too:

| Check | Modules |
|---|---|
| `security_header` | 7 Controls Verification, 9 Configuration Verification |
| `reflection` | 12 Exposure Verification |
| `http_method` | 5 Access Verification, 9 Configuration Verification |
| `cookie_flags` | 7 Controls Verification, 9 Configuration Verification |
| `cors` | 5 Access Verification, 6 Trust Verification |
| `tls_redirect` | 7 Controls Verification, 9 Configuration Verification |
| `clickjacking` | 7 Controls Verification |
| `directory_listing` | 11 Segregation Review, 12 Exposure Verification |
| `server_version` | 9 Configuration Verification, 12 Exposure Verification |

**Why Enigma covers module 1.** The Posture Review is the definition of scope,
rules and permitted actions before testing begins — which is exactly what
Enigma's authorization-first gate encodes and enforces (see
[authorization.md](authorization.md)).

## Declaring instruments

Add them to the assessment; they are recorded as *methodological* coverage:

```json
{
  "assessment_id": "ASM-00001",
  "target": { "url": "https://authorized-target.example" },
  "authorization": { "status": "authorized" },
  "scope": { "allowed_hosts": ["authorized-target.example"] },
  "methodology": "OSSTMM",
  "instruments": ["nmap", "whatweb", "nuclei", "OWASP ZAP"]
}
```

Names are matched case-insensitively with a few aliases (`OWASP ZAP` → `zap`).
An unrecognised instrument is **reported** in `unknown_instruments`, never
silently dropped.

The coverage checklist then appears in every report — JSON
(`summary.osstmm_modules`), Markdown, and the HTML report.

## Instruments are finders, not evidence

This is the boundary that keeps the framework honest:

> An instrument declares that a module was *exercised*. It does **not** prove a
> finding. Anything Nmap, WhatWeb, Nuclei or ZAP reports enters through the same
> adapter seam as OpenClaw and is still subject to Enigma's verification before
> it can affect a verdict or the RAV.

So declaring `nuclei` raises **module coverage**, never the security score.

## Honest gaps

Coverage is reported as it is, not rounded up:

- **Phase D (Intervention)** — quarantine, privileges, survivability, alert/log
  review — is **not covered**. It requires intrusive testing or internal access,
  outside Enigma's non-destructive remit.
- **Phase A modules 2–3** (Logistics, Active Detection Verification) are not
  covered by this instrument set.
- **Phase C modules 8, 10, 13** (Process Verification, Property Validation,
  Competitive Intelligence Scouting) are likewise uncovered.

With all five instruments declared and all nine checks run, coverage is
**7 / 17 modules (41 %)** — concentrated in phases B and C, which is what a
non-intrusive external web assessment can legitimately reach.

## API

```python
from enigma.methodologies.osstmm import compute_module_coverage

report = compute_module_coverage(
    instruments=["nmap", "whatweb", "nuclei", "zap", "enigma"],
    checks=["security_header", "cors", "reflection"],
)
report.covered, report.total, report.ratio
report.missing()          # modules not exercised
report.to_dict()          # per-phase breakdown with attribution
```

Reference: ISECOM, *OSSTMM 3*, Chapter 4 — Operational Security Testing (the
Four Point Process and the 17 modules of the test phases).
