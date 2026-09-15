# Security Test Audit Report (STAR)

**<client> — <channel> channel — <vector>**

## Audit identity

| Field | Value |
| --- | --- |
| Scope |  |
| Channel | Human / Physical / Wireless / Telecommunications / Data Networks |
| Vector |  |
| Index | how targets were uniquely identified |
| Test type | blind / double blind / gray box / double gray box / tandem / reversal |
| Test start (with TZ) |  |
| Test end (with TZ) |  |
| Duration of active testing |  |
| Analyst(s) |  |
| Authorization reference |  |
| Methodology | OSSTMM 3 (ISECOM), modules A–Q |

A rav is valid only for the scope, channel, vector and window stated above. Do
not quote the score without them.

## Coverage statement

| Module | Executed | Notes / why not |
| --- | --- | --- |
| A. Posture Review |  |  |
| B. Logistics |  |  |
| C. Active Detection Verification |  |  |
| D. Visibility Audit |  |  |
| E. Access Verification |  |  |
| F. Trust Verification |  |  |
| G. Controls Verification |  |  |
| H. Process Verification |  |  |
| I. Configuration / Training Verification |  |  |
| J. Property Validation |  |  |
| K. Segregation Review |  |  |
| L. Exposure Verification |  |  |
| M. Competitive Intelligence Scouting |  |  |
| N. Quarantine Verification |  |  |
| O. Privileges Audit |  |  |
| P. Survivability Validation |  |  |
| Q. Alert and Log Review |  |  |

Targets in scope that could not be reached, and the effect on the counts:

## Interference and error margin (module B)

Vantage point, latency and filtering observed, and anything that could have
distorted a count (rate limiting, WAF interposition, geo-blocking, shift
patterns, spectrum noise):

## rav

| Metric | Value |
| --- | --- |
| Visibility pores |  |
| Access pores |  |
| Trust pores |  |
| **Total porosity** |  |
| OpSec base |  |
| Controls sum |  |
| Missing coverage (total / A / B) |  |
| Coverage (total / A / B) |  |
| True controls base |  |
| Full controls base |  |
| Weighted limitations |  |
| Limitations base |  |
| Security delta |  |
| **Actual Security** | % |

Limitation weighting used: equal-weight (scripts/rav.py default) / ISECOM rav
calculator / custom weights — state which, and the tool version.

### Controls detail

| Control | Class | Verified count | Missing | Where verified |
| --- | --- | --- | --- | --- |
| Authentication | A |  |  |  |
| Indemnification | A |  |  |  |
| Resilience | A |  |  |  |
| Subjugation | A |  |  |  |
| Continuity | A |  |  |  |
| Non-repudiation | B |  |  |  |
| Confidentiality | B |  |  |  |
| Privacy | B |  |  |  |
| Integrity | B |  |  |  |
| Alarm | B |  |  |  |

### Limitations summary

| Limitation type | Count | Distinct findings |
| --- | --- | --- |
| Vulnerability |  |  |
| Weakness |  |  |
| Concern |  |  |
| Exposure |  |  |
| Anomaly |  |  |

## Findings

One entry per distinct finding. The count above is per affected target; the
entry below is per flaw.

### F-01 — <title>

| Field | Value |
| --- | --- |
| Limitation type | Vulnerability / Weakness / Concern / Exposure / Anomaly |
| Module | e.g. E. Access Verification |
| Affected targets | list by index; count = rav contribution |
| Control defeated | which of the 10, if any |
| First observed (TZ) |  |
| Detected by target | yes / no / unknown (from module Q) |

**What was verified.** What the analyst did and what the target did in response.

**Evidence.** Request/response, capture, photograph or log excerpt, with the
reference in the evidence package. Redact personal data.

**Reproduction.** Steps sufficient for the owner to reproduce.

**Effect.** What an actor gains, stated operationally — no severity score.

**Remediation options.** What would remove the limitation, and which control
would need to be added or fixed to cover the pore.

## Anomalies carried forward

Anything unexplained at the end of the audit, with what would be needed to
resolve it. Anomalies are reported, never dropped.

## Detection and response (modules C and Q)

Analyst timeline against the target's own records: what was logged, what alerted,
what was blocked, what passed unseen, and the discrepancies.

## Where coverage should go next

Ranked by effect on the rav, not by finding drama — usually the absent controls
across existing pores before the individual vulnerabilities.

| # | Action | Pores affected | Control added / limitation removed |
| --- | --- | --- | --- |

## Statement of limitations of this audit

What this report does not say: the scope not covered, the channels not audited,
the window it describes, and that the rav is a balance measurement of an attack
surface — not a risk rating, a compliance opinion, or a prediction of compromise.
