# Test fixtures

Shared inputs for the test suite. Fixtures represent **raw, un-normalized**
data as it would arrive from outside Enigma (chiefly OpenClaw), so tests can
assert that the normalizer and adapters tolerate real-world messiness without
silently inventing unsafe behaviour.

| Fixture | Purpose |
|---|---|
| `openclaw_raw_findings.json` | Messy OpenClaw output: missing `finding_id`, `id` instead of `finding_id`, out-of-range confidence, category-only findings (check inferred), an unknown category with no safe check, and a target without a path. |

Fixtures are loaded through the normal public path
(`StaticOpenClawAdapter.from_file`), so they exercise the same code the CLI uses.
