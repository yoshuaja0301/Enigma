# Connecting OpenClaw to Enigma

Enigma is designed so OpenClaw (or any client) can connect through whatever
surface fits its stack. **Every surface wraps the same facade**
(`enigma.service.EnigmaService`), so behaviour and the JSON contract are
identical no matter how you connect.

```
                         ┌───────────────────────────────┐
OpenClaw  ──────────────►│  Integration surface          │
  • HTTP / webhook       │   http_api · mcp_server ·      │
  • MCP (AI agent)       │   client SDK · OpenClawAdapter │
  • Python import        └───────────────┬───────────────┘
                                         ▼
                                 EnigmaService (facade)
                                         ▼
                     controller → engine (authorization-first)
```

The **authorization-first gate always applies**: no surface can cause a probe
outside the assessment's declared scope/authorization. In addition, a server may
set a **host allowlist** so an exposed endpoint cannot be turned into a
general-purpose scanner even if a request claims authorization.

---

## 1. Pull model — `OpenClawAdapter` (in-process)

If Enigma runs in the same process/pipeline as OpenClaw, just implement the
adapter interface (`get_findings`) — see
[openclaw-integration.md](openclaw-integration.md).

## 2. REST + webhook API

Run it:

```bash
enigma serve --host 127.0.0.1 --port 8737 \
  [--token SECRET] [--allow-host authorized-target.example] [--evidence-dir ./evidence]
# ENIGMA_API_TOKEN is also honoured for the bearer token
```

| Method & path | Body | Returns |
|---|---|---|
| `GET /health` | — | liveness + whether auth/allowlist are enabled |
| `POST /validate` | `{assessment}` | gate decision (`allowed`, `stage`, `reason`) |
| `POST /verify` | `{assessment, findings, callback_url?}` | full report |
| `POST /webhook/openclaw` | same as `/verify` | full report (push alias) |
| `GET /results/{assessment_id}` | — | last stored report |

- **Auth:** if a token is set, every route except `/health` requires
  `Authorization: Bearer <token>`.
- **Outbound webhook:** include `callback_url` and Enigma also POSTs
  `{event:"verification_complete", report:{...}}` there when it finishes.

Example:

```bash
curl -s -X POST http://127.0.0.1:8737/verify \
  -H 'Content-Type: application/json' \
  -d '{"assessment": {...}, "findings": [ {...} ], "callback_url": "https://openclaw.example/hook"}'
```

## 3. MCP server (for AI agents)

Enigma speaks the Model Context Protocol over stdio, so an AI agent like
OpenClaw can call it as tools. No third-party package required.

```bash
enigma mcp   # JSON-RPC 2.0 over stdio
```

Register that command as an MCP server on the agent side, e.g.:

```json
{
  "mcpServers": {
    "enigma": { "command": "enigma", "args": ["mcp", "--allow-host", "authorized-target.example"] }
  }
}
```

Tools exposed:

| Tool | Arguments | Purpose |
|---|---|---|
| `validate_scope` | `{assessment}` | run the gate only (no probes) |
| `verify_findings` | `{assessment, findings}` | verify and return a report |
| `get_result` | `{assessment_id}` | fetch a previous report |

## 4. Client SDK / connector

For Python consumers of the REST API:

```python
from enigma.integrations.client import EnigmaClient

client = EnigmaClient("http://localhost:8737", token="SECRET")
if client.validate(assessment)["allowed"]:
    report = client.verify(assessment, findings, callback_url="https://openclaw.example/hook")
```

---

## Safety notes for exposed deployments

- Set a **bearer token** (`--token` / `ENIGMA_API_TOKEN`) — do not expose an
  unauthenticated endpoint.
- Set a **host allowlist** (`--allow-host`, repeatable) so the server refuses any
  target outside it, regardless of what a request claims.
- Authorization in the assessment is operator-asserted; deploy the API only in a
  trusted environment and keep responsibility for authorization with the
  operator.
- `callback_url` is operator-supplied; restrict it to known OpenClaw hosts at the
  network layer if you enable outbound callbacks.
