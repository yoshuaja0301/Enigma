# Scoping, test types and Rules of Engagement

Read this before any active module. OSSTMM measurements are only comparable when
the scope, the channel and the test type are fixed in advance and written down.

## Scope, channel, vector, index

- **Scope** — the whole operational environment under audit, including assets you
  are allowed to see but not touch. State it as an enumerable list, not a phrase
  like "the production estate".
- **Channel** — the means of interaction. Audit each separately and compute a
  separate rav per channel: Human (HUMSEC), Physical (PHYSSEC), Wireless
  (SPECSEC), Telecommunications (TELSEC), Data Networks (COMSEC). A finding in
  one channel is not a finding in another.
- **Vector** — the direction of the audit: outside→in, inside→out, inside→inside,
  DMZ→internal, and so on. One vector per audit run; state it, because porosity
  counted from a different vantage point is a different number.
- **Index** — the key by which targets are uniquely identified (IP, MAC,
  hostname, number, name, badge, frequency). The index decides what "one target"
  means, and therefore what the counts mean.

## The six test types

Pick one and record it; it determines what both sides know and how the results
may be interpreted.

| Type | Analyst knows | Target knows | Common name |
|---|---|---|---|
| Blind | nothing of the target | the audit, scope and timing | ethical hacking, war game |
| Double blind | nothing of the target | nothing | black-box penetration test |
| Gray box | limited: defences and assets | scope and timing | vulnerability assessment |
| Double gray box | limited: defences and assets | scope and timing, not the vectors | white-box test |
| Tandem | everything | everything | crystal box, in-house audit |
| Reversal | everything | nothing | red team |

Two rules follow from the table and are worth stating to the client:

- A **double blind** measures detection and response as much as the target; the
  porosity count will be lower than reality because you cannot see everything in
  the time available. Report the coverage gap.
- A **tandem** audit yields the most accurate rav, because the index can be
  verified against the owner's own inventory. Prefer it when the client wants a
  metric they will track over time.

## Rules of Engagement checklist

Everything here should exist in writing before Phase II begins.

- [ ] Written authorization from a party entitled to grant it, naming the scope.
- [ ] Scope enumerated by index; third-party-hosted assets confirmed with the
      third party where their terms require it.
- [ ] Exclusions listed explicitly, including anything that must not be touched
      even if it answers.
- [ ] Test type, vector and channels agreed.
- [ ] Test window with time zone, plus any blackout periods.
- [ ] Named contacts for abort, escalation and out-of-hours incidents, both sides.
- [ ] Explicit sign-off for module P (continuity / survivability) or its exclusion.
- [ ] Explicit position on social engineering of named individuals (channel HUMSEC)
      and on any capture of personal data.
- [ ] Handling of anything discovered outside scope: stop, record, report — never
      pursue.
- [ ] Evidence handling: what is captured, where it is stored, how it is
      encrypted, when it is destroyed, and what is redacted before reporting.
- [ ] Agreement that credentials, keys or personal data encountered are reported,
      not used beyond the minimum needed to verify the finding.
- [ ] Deliverables and deadline: the STAR report, its rav table, and who receives it.

If the client asks for testing of assets they do not own or control, stop. If the
request is to test a person rather than a process, get that named and signed
separately. Absent written authorization, this skill's only legitimate output is
a scoping document.

## Trust properties (module F)

When counting trust pores, assess each relationship against the trust properties
enumerated in OSSTMM 3 (verify the wording against the manual before quoting it
in a report):

| Property | Question it answers |
|---|---|
| Size | How many parties is trust extended to? |
| Symmetry | Is trust one-way or mutual? |
| Visibility | How transparent is the trusted party's operation? |
| Subjugation | Who controls the terms of the interaction? |
| Consistency | What is the trusted party's historical failure record? |
| Integrity | Is change in the trusted party detectable? |
| Offsets | What compensation exists if the trust fails? |
| Value | What is gained by trusting, against what is risked? |
| Components | What further parties or systems does this trust depend on? |
| Porosity | How separated is the trusted party from its own environment? |

A trust relationship that fails most of these is still one trust pore. The
properties explain the finding; they do not change the count.

## Analyst discipline

- Measure, do not speculate. An interaction either happened and was recorded, or
  it is not a result.
- Record interference (module B) before results, so a later reviewer can tell a
  target's behaviour from the network's.
- Timestamp everything in one time zone and state which.
- Note every target that was in scope but not reached. Uncovered scope is a
  reported limitation of the audit, not a silent pass.
- Do not let a tool's severity rating enter the report. OSSTMM counts limitation
  types; severity is the owner's risk decision, made with the rav in hand.
