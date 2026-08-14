# Evidence

Every verified finding can carry sanitized, reviewable evidence. Evidence must
be safe to store and share: it never retains credentials, tokens, session
material or unnecessary personal data.

## Collection

`EvidenceCollector.collect(finding_id, exchanges, observations)` builds an
`Evidence` object with:

- `evidence_id` — e.g. `EV-00001`
- `exchanges` — per-request request/response snapshots (status, headers, a body
  excerpt), **sanitized**
- `observations` — the structured, sanitized observations from each probe
- `notes` — optional sanitized notes

## Sanitization (`EvidenceSanitizer`)

Redacted before anything is stored:

- **Headers**: `Authorization`, `Proxy-Authorization`, `Cookie`, `Set-Cookie`,
  `X-Api-Key`, `X-Auth-Token`, `X-Csrf-Token`, and similar → `[REDACTED]`.
- **Tokens in text**: `Bearer ...`, JWT-shaped tokens.
- **Sensitive params**: `password`, `token`, `secret`, `api_key`,
  `access_token`, `session`, ... — the name is kept, the value is redacted
  (`password=[REDACTED]`).
- **PII**: email addresses.

Sanitization is recursive over nested JSON-like structures, and errs toward
over-redaction.

## Storage (`EvidenceStore`)

In-memory by default. Provide a directory (or `--evidence-dir` on the CLI) to
persist each artifact as a sanitized `EV-XXXXX.json` file. Only sanitized
evidence ever reaches the store.

## Run manifest (`evidence/manifest.py`)

Sanitized evidence answers *what was observed*. The manifest answers *is this
still the evidence Enigma collected* — it is the paperwork that makes a report
checkable by someone who was not there.

Every report carries one under the top-level `manifest` key:

- a **run header** — Enigma version, interpreter, target, profile, declared
  instruments, a UTC timestamp, and the digest of the report's `summary`. Every
  field the manifest displays lives in the header, so nothing a reader is shown
  sits outside the digest;
- one **entry per finding** — verdict, status, source, the SHA-256 digest of the
  finding **as published in the report** (proof receipt included) and of its
  sanitized evidence artifact. Findings with no evidence, such as `reported`
  ones, are still recorded and chained;
- a **hash chain** — each entry's digest is folded into the previous one, so the
  final `chain_head` covers the whole run.

```python
from enigma.evidence import verify_report

problems = verify_report(report)            # [] when intact
problems = verify_report(report, evidence)  # also re-hash the stored artifacts
```

`evidence` is a mapping of evidence id to the stored dict, e.g.
`{e.evidence_id: e.to_dict() for e in store.all()}`.

| Tamper | Reported as |
|---|---|
| a published verdict or proof receipt rewritten | `published record N (F-1) does not match its recorded digest` |
| a summary metric or a `by_source` row rewritten | `report summary does not match its recorded digest` |
| a fabricated finding appended | `report carries 3 result(s) but the manifest records 2` |
| a manifest entry edited | `entry N (F-1) does not match its recorded digest` |
| entries reordered, inserted or dropped | `chain breaks at entry N (F-1); every later entry is affected` |
| the target, timestamp or any header field changed | `run header does not match the recorded genesis digest` |
| `chain_head` edited on its own | `chain_head does not match the recomputed chain` |
| a stored evidence file edited | `evidence EV-00001 does not match its recorded digest` |

`verify_manifest(manifest)` on its own checks only that the manifest is
*internally* consistent — it cannot vouch for a report it was never given.
`verify_report` is the call to reach for. A manifest built without the published
records says so (`manifest does not bind the report summary`) rather than passing
silently.

The digest is taken over the **sanitized** evidence — the same bytes a reader
sees — so checking integrity never requires un-redacted material.

### What it does and does not prove

It proves a report and its evidence were not altered *relative to each other*,
and pins them to a recorded time. It is **not a signature**: anyone who can
rewrite the whole manifest can recompute the chain. Publish or store
`chain_head` separately (a commit, a ticket, a lab notebook) if that matters.

Because the header includes a timestamp, two runs over identical input produce
different `chain_head` values — a manifest identifies *a run*, not an input.
Pass `generated_at` to `build_manifest()` to pin it when you need determinism.
