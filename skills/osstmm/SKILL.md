---
name: osstmm
description: Run an authorized OSSTMM 3 audit — scope and RoE, 5 channels x 17 modules, rav / Actual Security metrics, and a STAR report.
user-invocable: true
license: MIT
metadata:
  openclaw:
    version: 1.0.0
    methodology: OSSTMM 3 (ISECOM)
homepage: https://www.isecom.org/research.html
---

# OSSTMM 3 Operational Security Audit

Use this skill to plan, execute and report a security audit the OSSTMM way: measure
**what is operationally true** about a target's attack surface, not what a scanner
thinks is scary. Findings are counted, not rated by vibes, and the output is a
verifiable number (the **rav**) plus a **STAR** report.

OSSTMM vocabulary that drives everything below:

- **Scope** — everything in the operational environment being tested.
- **Channel** — the means of interaction with assets: Human, Physical, Wireless,
  Telecommunications, Data Networks. Each channel is audited separately.
- **Porosity** — the pores in the scope: **Visibility** (what can be seen),
  **Access** (where interaction is possible), **Trust** (interaction accepted
  without authentication). Porosity is the attack surface.
- **Controls** — 10 verified loss controls, 5 interactive (Class A) and 5 process
  (Class B), each measured against porosity.
- **Limitations** — counted flaws: Vulnerability, Weakness, Concern, Exposure, Anomaly.
- **rav** — the balance of porosity, controls and limitations. 100 = perfect balance.

## Hard gate: authorization before interaction

Do **not** run any active module (anything past Phase I) until all of these exist
in writing, from someone entitled to grant them:

1. Named scope — addresses, hosts, numbers, facilities, people, frequencies.
2. Explicit exclusions, and what is out of scope by default.
3. Test window, contact for abort, and the escalation path.
4. Test type agreed (blind / double blind / gray box / double gray box / tandem / reversal).
5. Sign-off for destructive or continuity testing (module P), if in scope at all.

If any is missing, stop and produce the RoE draft from
`templates/scope-and-roe.md` for the target owner to sign. Passive desk research on
public information (modules A, L, M) is the only work that proceeds without it, and
only against assets the requester owns.

## Workflow

1. **Define the scope and pick channels.** Write scope, channels and test type into
   the engagement record first — an audit whose scope moves is not measurable. Read
   `references/engagement.md` for the test types and the Rules of Engagement checklist.
2. **Generate the module checklist.** One per channel:
   `python3 {baseDir}/scripts/checklist.py --channel data-networks --out audit/data-networks.md`
   (`--channel all` for every channel; `--format json` to drive tooling.)
3. **Work the 17 modules in phase order** — Induction, Interaction, Inquest,
   Intervention. `references/channels-and-modules.md` gives each module's purpose,
   what counts as done, and channel-specific checks. Do not skip Phase I: posture,
   logistics and detection verification are what make the later counts trustworthy.
4. **Record every result as evidence, then count it.** A limitation exists only when
   it has been verified against the live target — reproduction steps, request/response
   or capture, timestamp, and the analyst who saw it. Unverified scanner output is an
   *Anomaly* at most, never a Vulnerability.
5. **Compute the rav.** Tally porosity, the 10 controls and the 5 limitations, then:
   `python3 {baseDir}/scripts/rav.py --visibility 12 --access 30 --trust 4 \
      --authentication 20 --indemnification 0 --resilience 12 --subjugation 6 --continuity 8 \
      --non-repudiation 4 --confidentiality 18 --privacy 2 --integrity 9 --alarm 11 \
      --vulnerability 3 --weakness 5 --concern 2 --exposure 7 --anomaly 1`
   Read `references/rav.md` before you trust the number — it defines what each input
   counts and where the arithmetic is authoritative versus indicative.
6. **Write the STAR.** `templates/star-report.md` is the Security Test Audit Report:
   scope, channel, index, test type, window, analysts, the rav table, and the counted
   limitations with their evidence. The report states what was verified and what was
   not reachable; gaps in coverage are reported as gaps, never as "clean".

## Counting rules that people get wrong

- Count **pores, not hosts**. One host with 3 reachable services is 3 access pores.
- A control counts **only where it is verified working**, per pore, per control type.
  10 controls x porosity is full coverage; anything less is missing coverage.
- A flaw that defeats a Class A control is a **Weakness**; one that defeats a Class B
  control is a **Concern**. A flaw giving access or privilege beyond permission is a
  **Vulnerability**. Public information that reveals targets is an **Exposure**.
  Anything unexplained is an **Anomaly** — and stays one until explained.
- The same flaw on 40 hosts is 40 limitations for the rav, one finding in the STAR.
- Actual Security going down after a remediation round usually means porosity was
  under-counted the first time. Re-index before blaming the target.

## Working with this repository

Enigma is an evidence-based verification framework, which maps onto OSSTMM cleanly:
verification is what turns a candidate finding into a counted limitation. When this
skill runs in that context, keep the evidence artifact (request, response, capture,
diff) as the primary record and treat the rav as derived — a number no one can trace
back to evidence is not an audit result.

## Reference map

| File | Read it when |
|---|---|
| `references/engagement.md` | scoping, test types, RoE, trust properties |
| `references/channels-and-modules.md` | executing any of the 17 modules |
| `references/rav.md` | tallying inputs or explaining the metric |
| `templates/scope-and-roe.md` | before any active testing |
| `templates/star-report.md` | writing up results |
| `scripts/checklist.py` | generating per-channel worksheets |
| `scripts/rav.py` | computing porosity / controls / limitations / Actual Security |

OSSTMM 3 is published by ISECOM at https://www.isecom.org — this skill operationalizes
it; the manual remains the authority.
