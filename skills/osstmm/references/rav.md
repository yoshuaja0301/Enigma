# The rav: porosity, controls, limitations, Actual Security

The rav is a count, not an opinion. It answers one question: *does the target's
verified protection balance the attack surface it exposes?* 100 is balance.
Below 100 means too few controls for the porosity and limitations measured.

Compute one rav per channel per vector. Aggregating channels into a single
company-wide number destroys the meaning of every input.

## Inputs

### Porosity — the attack surface

| Pore | Counts | Counting rule |
|---|---|---|
| **Visibility** | targets that can be seen from the vector | one per indexed target known to exist |
| **Access** | points where interaction is possible | one per interactive point, not per host |
| **Trust** | interactions accepted between targets without authentication | one per relationship |

A web server with HTTPS, SSH and an admin panel is 1 visibility pore and 3
access pores. If it also accepts an unauthenticated internal database
connection, that is 1 trust pore. Porosity `P` is the sum of all three.

High porosity is not insecurity. It is the surface against which controls are
measured — a large, fully controlled surface can still score 100.

### Controls — verified protection, per pore

Ten controls, counted only where an analyst verified them working. A control
documented in policy but not observed is not counted; it is a Process Verification
(module H) finding instead.

**Class A — interactive controls** (they act on the interaction itself)

| Control | Counts where |
|---|---|
| Authentication | interaction requires identity and credentials that are verified |
| Indemnification | liability and recourse are established (contract, warning, insurance) |
| Resilience | protection survives failure without opening access |
| Subjugation | the control, not the user, dictates how the interaction happens (no unsafe user choice) |
| Continuity | access is preserved under failure or delay (redundancy, failover) |

**Class B — process controls** (they act on the consequences)

| Control | Counts where |
|---|---|
| Non-repudiation | the interaction and its party are recorded undeniably |
| Confidentiality | the content of the interaction is kept between the parties |
| Privacy | the fact and means of the interaction are kept between the parties |
| Integrity | change is detectable by the parties |
| Alarm | the interaction triggers notification when it exceeds what is permitted |

Each control is counted per pore it protects, so the maximum meaningful count per
control is `P`, and full coverage is `10 x P`.

### Limitations — counted flaws

| Limitation | Definition | Typical example |
|---|---|---|
| **Vulnerability** | a flaw granting access or privilege beyond permission, or denying it to the legitimate | authentication bypass, RCE, path traversal |
| **Weakness** | a flaw that reduces or nullifies a **Class A** control | MFA that can be skipped, failover that opens access |
| **Concern** | a flaw that reduces or nullifies a **Class B** control | logging that omits the actor, weak transport ciphers |
| **Exposure** | information giving indirect visibility of targets or assets | verbose banners, indexed config, keys in public repos |
| **Anomaly** | any element that cannot be accounted for in normal operation | an unexplained listening port, an unattributable account |

Counting rules that decide the number:

- Count per affected target, not per finding. One missing security header across
  40 hosts is 40 Concerns in the rav and one finding in the STAR.
- Classify by **what the flaw defeats**, not by how alarming it sounds. If it
  defeats authentication (Class A) it is a Weakness; if it defeats logging
  (Class B) it is a Concern; if it gets you in, it is a Vulnerability.
- Unverified tool output is at most an Anomaly. Promote it only with evidence.
- An Anomaly stays an Anomaly until explained; do not quietly drop it.

## The arithmetic

```
P                  = visibility + access + trust
OpSec base         = (log10(1 + 100 * P)) ** 2
Controls sum       = sum of the 10 control counts
Full controls base = (log10(1 + 10 * Controls sum)) ** 2
missing(i)         = max(0, P - count(i))            for each control i
Missing coverage   = sum of missing(i)
Coverage           = 1 - Missing coverage / (10 * P)
True controls base = (log10(1 + 100 * (P - 0.1 * Missing coverage))) ** 2
Limitations base   = (log10(1 + 100 * weighted limitations)) ** 2
Security delta     = True controls base - OpSec base - Limitations base
Actual Security    = 100 + Security delta
```

Properties worth knowing:

- At full coverage with no limitations, True controls base equals OpSec base and
  Actual Security is exactly 100 — the definition of balance.
- **True** controls cap each control at `P`; **full** controls do not. They
  differ only when some control is counted more times than there are pores, which
  is the signal that a control is being over-claimed or the index is wrong.
- The log-square conversion means the first controls on a large surface buy far
  more than the last ones. That is intended: it rewards coverage over depth.

Run it:

```
python3 scripts/rav.py --visibility 12 --access 30 --trust 4 \
  --authentication 20 --resilience 12 --subjugation 6 --continuity 8 \
  --confidentiality 18 --integrity 9 --alarm 11 \
  --vulnerability 3 --weakness 5 --exposure 7
```

```
Total porosity            46        Controls sum              84
OpSec base             13.42        Missing coverage         376  (A 184, B 192)
                                    Coverage total          18.3%
                                    True controls base      8.55
Weighted limitations   15.00        Limitations base        10.09
Security delta        -14.95        Actual Security        85.05%
```

Reading it: the surface (13.42) is only partly controlled (8.55 — 18% coverage,
with indemnification, non-repudiation and privacy entirely absent) and carries 15
counted limitations (10.09). The result is 85.05%. The cheapest route upward is
coverage of the three absent controls across existing pores, not chasing the
three vulnerabilities.

## Honesty about the limitation weighting

OSSTMM 3 section 4.4 weights limitations by class and by the porosity and missing
controls they affect. `scripts/rav.py` defaults to **equal weight 1.0 per counted
limitation** — directionally correct, and enough to compare two runs against the
same target with the same method, but not the manual's weighting. Two options
when the figure is going into a client deliverable:

- compute the weighted sum with ISECOM's own rav calculator and pass it through:
  `--lim-weighted 12.7`; or
- set weights explicitly: `--weight vulnerability=1.5 --weight anomaly=0.5`.

Either way, state in the STAR which weighting produced the number. Everything
above the limitations line is exact and needs no such caveat.

ISECOM's spreadsheet also publishes a composite "rav" figure with cross-terms
between OpSec, full controls and limitations. This skill reports the widely used
`Actual Security = 100 + delta` form, which is exactly 100 at balance. If a client
tracks the spreadsheet's composite value, take that number from the spreadsheet
rather than re-deriving it here.

## Interpreting a rav honestly

- A rav is a measurement of one scope, one channel, one vector, at one time. Say
  all four next to the number, every time.
- A rising Actual Security across audits means controls were added or porosity
  reduced. Verify which — a "improvement" produced by a smaller index is an
  accounting artifact, and re-indexing is the first thing to check.
- Missing coverage is the actionable output, not the score. Report the per-control
  missing counts; that table is what a defender can act on this quarter.
- Never present a rav as a risk rating or a probability of compromise. It is the
  balance of an attack surface, and the risk decision belongs to the target owner.
