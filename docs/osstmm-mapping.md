# OSSTMM mapping

Enigma maps each verified finding onto a pragmatic subset of the OSSTMM (Open
Source Security Testing Methodology Manual) structure. This is a mapping aid for
analysis and reporting — not a claim of OSSTMM certification.

## What is mapped

`OsstmmMapper.map(finding, verdict)` returns:

```json
{
  "name": "OSSTMM",
  "channel": "COMSEC/Data Networks",
  "section": "Configuration & Hardening",
  "controls": ["Confidentiality", "Integrity"],
  "verdict": "CONFIRMED",
  "vector": "authorized-target.example/search"
}
```

Web assessment lives in the **COMSEC / Data Networks** channel.

## Mapping table (by `check`)

| `check` | Section | Operational controls |
|---|---|---|
| `security_header` | Configuration & Hardening | Confidentiality, Integrity |
| `reflection` | Integrity | Integrity, Subjugation |
| `http_method` | Access Control | Authentication, Subjugation |
| *(default / unknown)* | Information Leakage | Confidentiality |

The mapping is keyed on the verification `check`, so it stays stable regardless
of the free-text title an AI produced.

## Operational controls

Enigma uses the OSSTMM ten operational controls, split into Class A
(interactive: Authentication, Indemnification, Resilience, Subjugation,
Continuity) and Class B (process: Non-Repudiation, Confidentiality, Privacy,
Integrity, Alarm). See `methodologies/osstmm/controls.py`.

## Coverage

`OsstmmMapper.coverage(findings)` counts how many findings touched each section —
a simple signal of assessment breadth for the research questions.
