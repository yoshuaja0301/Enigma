# Channels and the 17 modules

Derived from `assets/modules.json`, which is the source of truth for both this
reference and `scripts/checklist.py`. Edit the JSON, not this file, and keep them
in step.

Work the modules in phase order, per channel. Phase I is what makes the later
counts trustworthy: skip it and you are reporting your own network's behaviour.

## Channels

| Channel | Code | Scope | Index by |
| --- | --- | --- | --- |
| Human Security | `human-security` (HUMSEC) | People, their interactions, and the psychological and physical means of reaching them. | Names, roles, contact points (each person reachable through a channel is a target). |
| Physical Security | `physical-security` (PHYSSEC) | Tangible, non-electronic barriers and controls: sites, doors, locks, guards, racks, media, waste. | Locations, entry points, enclosures, storage. |
| Wireless Communications | `wireless-communications` (SPECSEC) | All electronic emanation within the scope: 802.11, Bluetooth, RFID/NFC, infrared, cellular, radio, and unintended emissions. | BSSIDs/SSIDs, device MACs, tag IDs, frequencies, emitters. |
| Telecommunications | `telecommunications` (TELSEC) | Voice and telephony networks: PSTN lines, PBX, VoIP, voicemail, fax, conferencing, modems. | Numbers, extensions, SIP URIs, trunks, mailboxes. |
| Data Networks | `data-networks` (COMSEC) | Wired and routed networks, systems, services and applications reachable over them. | IP addresses, hostnames, URLs/endpoints, ports and services, accounts. |

Each channel is audited and scored separately. The same asset can be a target in
several channels — a laptop is a data-networks target, a wireless target, and a
physical target — and each is counted in its own rav.

## Phases

- **Phase I — Induction**: Establish the truth of the environment: what rules apply, what interference distorts measurement, and whether the target detects interaction at all.
- **Phase II — Interaction**: Measure the attack surface: visibility, access, trust, and the process controls protecting them.
- **Phase III — Inquest**: Measure what the target emanates: processes, configuration, property, segregation, exposure and competitive intelligence.
- **Phase IV — Intervention**: Measure what happens under interference: containment, privilege misuse, continuity, and what the target actually recorded.

## Modules

### Phase I — Induction

#### A. Posture Review

**Purpose.** Establish the culture, rules, regulations, legislation, contracts and policies that govern the scope, and the ones the audit itself must obey.

**Done when.** Applicable obligations are listed with their source, and any that conflict with the planned tests are resolved or excluded in writing.

| Channel | What to check |
| --- | --- |
| Human Security | HR policy, acceptable-use and awareness obligations; local law on recording, pretexting and employee privacy. |
| Physical Security | Site rules, fire/safety codes, lease and landlord limits, camera and badge-data retention law. |
| Wireless Communications | Spectrum regulation, transmit-power limits, legality of capture and jamming in the jurisdiction. |
| Telecommunications | Wiretap and recording law, carrier terms, emergency-service (911/112) prohibitions on test calls. |
| Data Networks | Provider and cloud test policies, data-protection duties over anything captured, third-party hosting consent. |

#### B. Logistics

**Purpose.** Measure the interference between analyst and target — latency, distance, filtering, geography, language, time of day — so later measurements are not artifacts of the path.

**Done when.** Vantage points, baseline timings and known distortions are recorded, and the index is reachable from the agreed position.

| Channel | What to check |
| --- | --- |
| Human Security | Language, time zones, working hours, cultural norms that change how a person responds. |
| Physical Security | Travel, sightlines, weather, lighting, shift patterns of the site. |
| Wireless Communications | Distance, antenna and gain, noise floor, obstructions, channel congestion. |
| Telecommunications | Trunk quality, carrier routing, IVR timeouts, call-detail delays. |
| Data Networks | Route and latency baselines, upstream filtering, CDN/WAF interposition, rate limits, NAT and geo-blocking. |

#### C. Active Detection Verification

**Purpose.** Verify the breadth and predictability of the target's detection, logging and response before you rely on stealth or on the target's own records.

**Done when.** It is known what interaction is detected, how fast, by whom, and whether response is consistent enough to be predicted.

| Channel | What to check |
| --- | --- |
| Human Security | Whether staff report approaches, to whom, and how quickly the report travels. |
| Physical Security | Guard rounds, camera coverage and review, alarm zones and response time. |
| Wireless Communications | Rogue-AP and WIDS detection, deauth alerting, client-side warnings. |
| Telecommunications | Fraud/toll alerting, call-pattern monitoring, voicemail lockout thresholds. |
| Data Networks | IDS/WAF/EDR reaction, blocking thresholds, ticket generation, whether blocks are per-IP, per-session or permanent. |

### Phase II — Interaction

#### D. Visibility Audit

**Purpose.** Enumerate what of the scope can be seen from the agreed vantage point. Each visible target is a Visibility pore.

**Done when.** The index is complete and de-duplicated, every entry traceable to how it was discovered, and Visibility is a defensible count.

| Channel | What to check |
| --- | --- |
| Human Security | People discoverable as reachable targets: directories, org charts, social profiles, conference and vendor lists. |
| Physical Security | Visible entrances, windows, enclosures, equipment and signage identifying assets. |
| Wireless Communications | Beaconing and non-beaconing networks, paired devices, tags and emitters detectable in scope. |
| Telecommunications | Live numbers in the block, extensions, mailboxes, fax and modem answers. |
| Data Networks | Live hosts, open ports, services and versions, virtual hosts, endpoints and APIs, cloud assets. |

#### E. Access Verification

**Purpose.** Measure the breadth and depth of interactive access points — every place interaction is possible, authenticated or not. Each is an Access pore.

**Done when.** Every access point is enumerated with the interaction it permits, and Access is counted per point rather than per system.

| Channel | What to check |
| --- | --- |
| Human Security | Each channel a person actually answers on: phone, mail, chat, in-person, plus who they will accept requests from. |
| Physical Security | Doors, gates, windows, hatches, ports and drop points that admit interaction. |
| Wireless Communications | Associable networks, open pairing, readable/writable tags, receivers that accept input. |
| Telecommunications | Answering endpoints, IVR branches, DISA, voicemail systems, conference bridges. |
| Data Networks | Each service, endpoint, parameter surface, login, upload and admin interface that accepts input. |

#### F. Trust Verification

**Purpose.** Determine where targets accept interaction from each other without authentication. Each such relationship is a Trust pore.

**Done when.** Trust relationships are mapped between indexed targets and assessed against the trust properties (see references/engagement.md).

| Channel | What to check |
| --- | --- |
| Human Security | Who is believed without verification: internal callers, vendors, badge-wearers, authority claims. |
| Physical Security | Areas entered without re-authentication once inside, shared keys, tailgating tolerance. |
| Wireless Communications | Auto-join profiles, remembered SSIDs, trusted pairings, unauthenticated management frames. |
| Telecommunications | Caller-ID trust, internal-extension privilege, voicemail access from inside the PBX. |
| Data Networks | Allow-listed IPs, host trust, service accounts, SSO/token trust, internal APIs assumed private. |

#### G. Controls Verification

**Purpose.** Measure the use and effectiveness of the five process (Class B) controls: non-repudiation, confidentiality, privacy, integrity, alarm.

**Done when.** Each process control is counted only where verified working against a specific pore, and flaws in them are recorded as Concerns.

| Channel | What to check |
| --- | --- |
| Human Security | Identity recording, discretion in handling requests, confidential channels, verification steps, reporting duty. |
| Physical Security | Badge and visitor records, shielding from observation, tamper seals, alarms. |
| Wireless Communications | Link encryption, MAC/identifier privacy, frame integrity, rogue alarming. |
| Telecommunications | Call logging and CDR retention, encrypted voice, number privacy, fraud alarms. |
| Data Networks | Audit logging, transport and at-rest encryption, PII minimization, signing/hashing, alerting on abuse. |

### Phase III — Inquest

#### H. Process Verification

**Purpose.** Test whether the controls found are maintained as documented — due diligence under normal and abnormal conditions, not just on the day of the audit.

**Done when.** Each claimed process has been exercised or evidenced, and drift between documented and operational state is recorded.

| Channel | What to check |
| --- | --- |
| Human Security | Whether verification, escalation and reporting procedures are followed when inconvenient. |
| Physical Security | Whether visitor, key-issue and disposal procedures hold during shift change and after hours. |
| Wireless Communications | Whether rogue findings are acted on and provisioning follows the standard. |
| Telecommunications | Whether extension, mailbox and trunk changes follow change control. |
| Data Networks | Patch, onboarding/offboarding, backup-restore, certificate renewal and incident procedures under load. |

#### I. Configuration / Training Verification

**Purpose.** Compare the operational state to the intended state: configuration for technical channels, training and awareness for the human channel. Establishes whether controls override operational need or the reverse.

**Done when.** Defaults, deviations and unmanaged assets are documented against the intended baseline.

| Channel | What to check |
| --- | --- |
| Human Security | Training content, recency and coverage; what staff actually do versus what training says. |
| Physical Security | Lock grades, door closers, camera aim, safe settings, fire-path overrides. |
| Wireless Communications | Cipher suites, WPS/legacy protocols, transmit power, guest isolation, default credentials. |
| Telecommunications | Default and unchanged mailbox PINs, call-forward and DISA settings, unused trunks. |
| Data Networks | Hardening baselines, default credentials and pages, TLS configuration, permissive CORS/headers, exposed debug. |

#### J. Property Validation

**Purpose.** Identify intellectual and physical property within the scope that is breached, misused, unlicensed or illegally held.

**Done when.** Property held in scope is inventoried against entitlement, and misuse is recorded with evidence rather than assumption.

| Channel | What to check |
| --- | --- |
| Human Security | Company data on personal accounts and devices, shared credentials, unsanctioned tools. |
| Physical Security | Unlicensed media, unaccounted equipment, documents and disposal-bound material left recoverable. |
| Wireless Communications | Unauthorized APs and hotspots, rogue tags and devices carrying company data. |
| Telecommunications | Unauthorized lines, forwarding of business calls to private numbers, unsanctioned conferencing. |
| Data Networks | Unlicensed software, leaked source or keys, shadow-IT services and data holding company property. |

#### K. Segregation Review

**Purpose.** Determine the separation between personal information and business information, and the exposure of personal data within the scope.

**Done when.** Where PII mixes with business assets is identified, with the pores through which it is reachable.

| Channel | What to check |
| --- | --- |
| Human Security | Personal details discoverable through work channels; use of personal accounts for business. |
| Physical Security | Personal effects and records in business areas, unsecured HR and medical files. |
| Wireless Communications | Personal devices on business networks, device identifiers broadcasting people's movements. |
| Telecommunications | Personal numbers in business directories, voicemail containing personal data. |
| Data Networks | PII in logs, backups, test data, tickets and error messages; cross-tenant or cross-user leakage. |

#### L. Exposure Verification

**Purpose.** Discover freely available information that gives indirect visibility of targets or assets in scope. Each such item is an Exposure limitation.

**Done when.** Public sources have been searched systematically and each exposure is recorded with its source and what it reveals.

| Channel | What to check |
| --- | --- |
| Human Security | Staff lists, roles, absences, photographs of badges and screens, recruitment detail. |
| Physical Security | Street and satellite imagery, floor plans, permit filings, vendor case studies. |
| Wireless Communications | Public wardriving databases, device registration lookups, FCC/type filings. |
| Telecommunications | Published number ranges, directory entries, leaked call detail. |
| Data Networks | Certificate transparency, DNS and passive DNS, code and config in public repos, paste sites, search-engine indexes, cached errors. |

#### M. Competitive Intelligence Scouting

**Purpose.** Derive, from the scope alone, information of competitive value to the target owner — what an adversary learns about the business by watching its infrastructure.

**Done when.** Business-impacting inferences are documented with the technical observations that support them.

| Channel | What to check |
| --- | --- |
| Human Security | Hiring, reorganization and partnership signals from people's public activity. |
| Physical Security | Deliveries, expansion works, occupancy and equipment visible from outside. |
| Wireless Communications | Vendor fingerprints and device populations revealing platform choices. |
| Telecommunications | Call volumes, IVR menus and site presence revealing operations and scale. |
| Data Networks | Technology stack, third-party dependencies, staging and pre-release assets, growth inferred from infrastructure. |

### Phase IV — Intervention

#### N. Quarantine Verification

**Purpose.** Determine whether hostile or anomalous interaction is contained — in both directions — and how allow/deny decisions are made.

**Done when.** Containment behaviour is measured for inbound and outbound interaction, including how long it lasts and how it is lifted.

| Channel | What to check |
| --- | --- |
| Human Security | Whether a suspicious approach is cut off and circulated, or just individually ignored. |
| Physical Security | Mantraps, holding areas, escort rules, whether an unbadged person is stopped rather than merely noticed. |
| Wireless Communications | Client isolation, rogue containment, deauth of unknown devices, guest segmentation. |
| Telecommunications | Call blocking, mailbox lockout, fraud cut-off, whether blocks persist. |
| Data Networks | Segmentation and egress filtering, WAF/EDR blocking duration, session invalidation, account lockout. |

#### O. Privileges Audit

**Purpose.** Map credentials and privilege levels and measure the impact of their misuse — including escalation that was never earned.

**Done when.** Privilege boundaries are tested from each authenticated position available, and every crossing is evidenced.

| Channel | What to check |
| --- | --- |
| Human Security | What a person will do for a claimed authority; what access an ordinary role can obtain by asking. |
| Physical Security | Where a visitor or contractor badge reaches; master-key and override scope. |
| Wireless Communications | Guest-to-internal reachability, management-interface access from the air. |
| Telecommunications | Extension-to-admin functions, DISA to outbound trunks, mailbox-to-mailbox access. |
| Data Networks | Horizontal and vertical access control, token and role handling, admin surface, service-account reach. |

#### P. Survivability Validation / Service Continuity

**Purpose.** Measure the target's resilience to excessive, adverse or interrupted conditions — continuity, failover and graceful failure. Requires explicit written sign-off; skip the module and say so if it is not granted.

**Done when.** Either resilience is measured within the authorized envelope, or the module is recorded as excluded with the reason.

| Channel | What to check |
| --- | --- |
| Human Security | Cover during absence, single points of human failure, whether a refused request has a documented fallback. |
| Physical Security | Power, cooling, access during outage, whether fail-safe means open or locked. |
| Wireless Communications | Behaviour under interference and congestion, fallback to weaker modes. |
| Telecommunications | Trunk failover, behaviour when lines saturate, emergency routing (never test live emergency services). |
| Data Networks | Failover and degradation under load, dependency failure handling, backup restore, rate-limit behaviour. |

#### Q. Alert and Log Review

**Purpose.** Compare the audit's own record of activity to what the target detected and recorded. The end survey: what really got seen.

**Done when.** The analyst timeline is reconciled against the target's logs and alerts, and every gap or discrepancy is reported.

| Channel | What to check |
| --- | --- |
| Human Security | Which approaches were reported, by whom, how accurately, and what was done with the report. |
| Physical Security | Guard logs, visitor books, badge and camera records against the actual visits. |
| Wireless Communications | WIDS and controller logs against the associations and captures performed. |
| Telecommunications | CDRs and fraud alerts against the calls placed. |
| Data Networks | IDS/WAF/EDR/application logs against the requests sent, including what was silently dropped. |

## What each module feeds

| Module | Feeds |
| --- | --- |
| A. Posture Review | audit constraints; obligations cited in the STAR |
| B. Logistics | interference record; error margin for every later count |
| C. Active Detection Verification | detection baseline; validates module Q and any stealth claim |
| D. Visibility Audit | **Visibility** pore count |
| E. Access Verification | **Access** pore count |
| F. Trust Verification | **Trust** pore count; trust-property assessment |
| G. Controls Verification | Class B control counts; **Concern** limitations |
| H. Process Verification | Class A/B control counts where processes are exercised; **Weakness**/**Concern** |
| I. Configuration / Training Verification | control counts against baseline; **Weakness**, **Concern**, **Vulnerability** |
| J. Property Validation | property findings; **Exposure** where property reveals assets |
| K. Segregation Review | privacy control count; **Concern** and **Exposure** for PII |
| L. Exposure Verification | **Exposure** limitations |
| M. Competitive Intelligence Scouting | business-impact narrative for the STAR (not a rav input on its own) |
| N. Quarantine Verification | Subjugation, Resilience and Alarm control counts; **Weakness** |
| O. Privileges Audit | Authentication and Subjugation control counts; **Vulnerability** |
| P. Survivability Validation / Service Continuity | Continuity and Resilience control counts; **Weakness** |
| Q. Alert and Log Review | Non-repudiation and Alarm control counts; **Anomaly** for anything unlogged; audit coverage statement |

An **Anomaly** can come out of any module. If a module produced something you
cannot explain, it is counted, not dropped.
