# Tool parsers — Nuclei, OWASP ZAP, Nmap and WhatWeb

These tools are **finders**, exactly like OpenClaw: they report what they
*suspect*. Their output enters Enigma through the same adapter seam and is still
verified before it can affect a verdict or the RAV.

```bash
enigma verify --assessment a.json \
  --nuclei  nuclei.jsonl \
  --zap     zap-report.json \
  --nmap    scan.xml \
  --whatweb whatweb.json
```

All flags are repeatable and can be combined with `--findings` (OpenClaw
output). `enigma prove` accepts them too.

```python
from enigma.agent.tools import PARSERS, ToolFindingAdapter, parse_nmap

findings = parse_nmap("scan.xml")                # path, file object, or raw text
adapter  = ToolFindingAdapter.from_whatweb("whatweb.json")
PARSERS["nuclei"]("nuclei.jsonl")                # dispatch by tool name
```

## What the parsers do

| Input | Becomes |
|---|---|
| Nuclei JSONL (`nuclei -jsonl`), or a JSON array | one finding per result |
| ZAP JSON report (`site[] → alerts[] → instances[]`) | one finding **per instance**, so a verdict is tied to a concrete URL |
| Nmap XML (`nmap -oX`) | one finding per open port, plus service-banner and NSE-script findings |
| WhatWeb JSON (`--log-json`, JSONL or array) | one finding per **security-relevant** plugin |

A finding that maps onto one of Enigma's nine safe checks carries `check` +
`parameters` and is **verified automatically**. Anything else keeps status
`reported` — never dropped, never probed unsafely.

### Mapping

**ZAP** is matched on the stable `pluginid` first, then on the alert name:

| Plugin | Alert | Check |
|---|---|---|
| 10038 | CSP Header Not Set | `security_header` (Content-Security-Policy) |
| 10035 | HSTS Header Not Set | `security_header` (Strict-Transport-Security) |
| 10021 | X-Content-Type-Options Missing | `security_header` |
| 10020 | Missing Anti-clickjacking Header | `clickjacking` |
| 10010 / 10011 / 10054 | Cookie missing HttpOnly / Secure / SameSite | `cookie_flags` |
| 10033 | Directory Browsing | `directory_listing` |
| 10036 / 10037 | Server leaks version information | `server_version` |
| 10098 | Cross-Domain Misconfiguration | `cors` |
| 40012 | Reflected XSS | `reflection` (uses the reported `param`) |

**Nuclei** is matched on template id, tags, name and `matcher-name` — e.g.
`http-missing-security-headers` + `matcher-name: content-security-policy` →
`security_header`; `dir-listing` → `directory_listing`; `cors*` → `cors`.

**Nmap** works at the port/service layer while Enigma verifies at the HTTP layer,
so the mapping is deliberately narrow — only what Enigma can actually prove:

| Nmap output | Check |
|---|---|
| service `product`/`version` on an HTTP service | `server_version` |
| NSE `http-methods` advertising TRACE/PUT/DELETE/… | `http_method` |
| NSE `http-server-header`, `http-generator` | `server_version` |
| NSE `http-security-headers` naming a header | `security_header` |
| NSE `http-cors` | `cors` |
| **an open port itself** | *(none)* — kept as `reported` |

An open port is not something Enigma can verify over HTTP, so it is recorded, not
proven. Non-HTTP services (SSH on 22) never become HTTP checks, and closed or
filtered ports are ignored entirely.

**WhatWeb** mostly reports *inventory*, not security observations. `Title`,
`Country`, `IP`, `HTML5` and similar are **not** turned into findings — doing so
would bury the real ones. A plugin becomes a finding when it reports a **version**
(→ `server_version`) or is a known disclosure header (`HTTPServer`,
`X-Powered-By`, …). A technology identified without a version is kept as
`reported`. The names of skipped metadata plugins are preserved under
`tool.skipped_metadata_plugins`, so the omission is visible rather than silent.

Where a required parameter cannot be determined (which header? which cookie
flag?), the check is **dropped to `reported`** rather than run under-specified.

## Severity is a hypothesis, not evidence

A tool's severity/confidence is carried into the finding's `confidence` field —
the same slot OpenClaw's confidence uses, which verification never reads:

- Nuclei `severity`: critical 0.9 · high 0.8 · medium 0.65 · low 0.5 · info 0.3
- ZAP `confidence`: High 0.85 · Medium 0.65 · Low 0.4 · False Positive 0.1
- Nmap: banner/NSE findings 0.6–0.7 · open port 0.5
- WhatWeb: parsed version 0.7 · disclosure header without version 0.55 ·
  technology only 0.4

`riskcode` / template id / plugin id / CWE are retained under `tool` as
provenance, and the finder is visible in every report as `finding.source`.

This is the point. In a real run:

```
ID           SOURCE   TOOL CLAIM   ENIGMA VERDICT   OBSERVED
NUCLEI-0001  nuclei   0.30         CONFIRMED        page can be framed (no X-Frame-Options)
NUCLEI-0002  nuclei   0.90         INCONCLUSIVE     no automatic check — reported for review
ZAP-0001     zap      0.85         CONFIRMED        reply did NOT include CSP
ZAP-0002     zap      0.85         NOT_CONFIRMED    reply DID include CSP   ← ZAP false positive
ZAP-0003     zap      0.85         CONFIRMED        cookie 'sid' set without HttpOnly
```

ZAP was *High confidence* that CSP was missing on `/secure`; the server disagreed
and Enigma recorded the refutation. A Nuclei *info* finding was nonetheless real.
Tool confidence and truth are orthogonal — which is exactly why the verdict is
computed from the server's reply instead.

## Scope still applies

A tool may report URLs outside the assessment's scope (ZAP spiders broadly). The
authorization gate blocks those: the finding comes back `blocked` /
`INCONCLUSIVE` and **no request is sent**. Widen `scope.allowed_hosts` only if
the extra hosts are genuinely authorized.

## Robustness and safety

- Blank and malformed lines in Nuclei/WhatWeb JSONL are skipped, not fatal.
- ZAP `site` may be an object or a list; alerts without `instances` still yield
  one finding.
- Inputs may be a path, an open file object, bytes, or raw text.
- An unparseable ZAP report raises `ValueError`; unusable Nmap XML raises
  `NmapParseError` — rather than silently returning nothing.
- **XML safety:** `xml.etree.ElementTree` is not hardened against
  entity-expansion ("billion laughs") attacks. Nmap never emits `<!ENTITY`, so
  input containing an entity declaration is **rejected outright** instead of
  parsed. (Nmap's own `<!DOCTYPE nmaprun>` is fine and still accepted.)
- Nmap findings carry the scanned port under `tool.port` as provenance, but
  verification targets the URL configured in the assessment — a finding about a
  port other than the target's is recorded, not silently probed elsewhere.

See also [osstmm-modules.md](osstmm-modules.md) — declaring an instrument records
*methodological* coverage; parsing its output is what turns it into findings.
