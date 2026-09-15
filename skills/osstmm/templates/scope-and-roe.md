# Scope and Rules of Engagement — <client> / <engagement name>

Status: **DRAFT — no active testing until signed**

## 1. Parties

| Role | Name | Organization | Contact | Time zone |
| --- | --- | --- | --- | --- |
| Target owner (authorizing) |  |  |  |  |
| Technical point of contact |  |  |  |  |
| Abort / emergency contact |  |  |  |  |
| Lead analyst |  |  |  |  |
| Analyst(s) |  |  |  |  |

Authorizing signatory confirms they are entitled to authorize testing of every
asset listed in section 3, including any hosted by a third party.

## 2. Audit definition

| Item | Value |
| --- | --- |
| Channels | Human / Physical / Wireless / Telecommunications / Data Networks |
| Test type | blind / double blind / gray box / double gray box / tandem / reversal |
| Vector(s) | e.g. Internet → DMZ, DMZ → internal, internal → internal |
| Index | how a target is uniquely identified (IP, hostname, number, name, BSSID) |
| Window | start — end, with time zone |
| Blackout periods |  |
| Objective | what the owner intends to decide with the result |

## 3. Scope

Targets in scope (enumerate by index; attach an inventory if long):

| # | Target | Index value | Owner | Notes |
| --- | --- | --- | --- | --- |
| 1 |  |  |  |  |

Explicitly **out of scope** (must not be interacted with even if reachable):

| # | Target / range | Reason |
| --- | --- | --- |
| 1 |  |  |

Third-party-hosted assets and the status of their provider's test policy:

| Asset | Provider | Authorization status |
| --- | --- | --- |

## 4. Permitted and prohibited activity

| Activity | Permitted | Conditions |
| --- | --- | --- |
| Passive reconnaissance and public-source research | yes / no |  |
| Port and service enumeration | yes / no |  |
| Authenticated testing (credentials supplied) | yes / no |  |
| Exploitation to confirm a finding | yes / no | minimum interaction needed to evidence it |
| Privilege escalation (module O) | yes / no |  |
| Social engineering of named individuals (HUMSEC) | yes / no | names listed separately and signed |
| Physical entry attempts (PHYSSEC) | yes / no | with written carry letter |
| Wireless capture / association (SPECSEC) | yes / no | jamming prohibited |
| Telephony testing (TELSEC) | yes / no | emergency numbers never dialled |
| Continuity / survivability testing (module P) | yes / no | **requires explicit sign-off below** |
| Persistence, backdoors, implants | no | never |
| Data exfiltration beyond proof of access | no | never |
| Modification or deletion of client data | no | never |

Continuity testing sign-off (module P), if permitted:

> I authorize testing that may degrade or interrupt the availability of the
> in-scope assets listed above, within the agreed window.
>
> Name / role / date: ______________________

## 5. Handling rules

- Out-of-scope discovery: stop, record, report; do not pursue.
- Credentials, keys or personal data encountered: reported, used only to the
  minimum extent needed to verify the finding, never retained beyond the report.
- Evidence store: <location>, encrypted at rest, access limited to the analysts
  named above, destroyed <retention period> after report acceptance.
- Personal data captured is redacted before reporting unless the owner directs
  otherwise in writing.
- Critical finding during the engagement: notify the technical contact within
  <n> hours rather than waiting for the report.

## 6. Deliverables

| Deliverable | Format | Due |
| --- | --- | --- |
| Security Test Audit Report (STAR) per channel, with rav |  |  |
| Evidence package |  |  |
| Read-out / debrief |  |  |

## 7. Acceptance

| Party | Name | Signature | Date |
| --- | --- | --- | --- |
| Target owner |  |  |  |
| Lead analyst |  |  |  |

No module beyond Phase I (Induction) begins before both signatures are in place.
