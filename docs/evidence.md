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
