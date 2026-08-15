# MCP integration example

This folder shows OpenClaw (or any MCP-capable AI agent) connecting to Enigma
over the **Model Context Protocol** and having its potential findings verified.

## Run the end-to-end demo

```bash
python examples/mcp/openclaw_agent_demo.py
```

It needs no installation and no external network. The script:

1. starts a throwaway **authorized target** on `127.0.0.1`,
2. launches Enigma as an MCP server (`enigma mcp --allow-host 127.0.0.1`),
3. acts as a **simulated OpenClaw agent** over stdio JSON-RPC:
   `initialize → tools/list → validate_scope → verify_findings → get_result`.

Expected output (verdicts are real, computed by probing the local target):

```
=== Enigma verdicts (AI finds, Enigma verifies) ===
  OC-1   CONFIRMED       repro=True   ai=0.72  → Missing CSP on /
  OC-2   NOT_CONFIRMED   repro=True   ai=0.63  → Missing CSP on /secure (likely false positive)
  OC-3   CONFIRMED       repro=True   ai=0.80  → Query input reflected on /search
  OC-4   CONFIRMED       repro=True   ai=0.55  → TRACE method appears enabled

Summary: 3 confirmed · 1 not-confirmed (false positive) · 0 inconclusive  (of 4)
```

`OC-2` is Enigma catching an OpenClaw **false positive**: `/secure` actually
sets a CSP header, so the "missing CSP" hypothesis is `NOT_CONFIRMED`.

## Register Enigma as an MCP server in a real agent

After `pip install -e .`, add an entry like [`mcp_config.json`](mcp_config.json):

```json
{
  "mcpServers": {
    "enigma": {
      "command": "enigma",
      "args": ["mcp", "--allow-host", "authorized-target.example"]
    }
  }
}
```

- Use `--allow-host` (repeatable) so the server only ever probes hosts you
  allow-list, regardless of what a finding claims.
- If `enigma` is not on `PATH`, use the module form instead:
  `"command": "python", "args": ["-m", "enigma", "mcp", "--allow-host", "..."]`
  (set `PYTHONPATH` to the repo's `src/` when running from a checkout).

## The MCP tools

| Tool | Arguments | Returns |
|---|---|---|
| `validate_scope` | `{assessment}` | gate decision (`allowed`, `stage`, `reason`) |
| `verify_findings` | `{assessment, findings}` | full report (verdicts + evidence + OSSTMM) |
| `get_result` | `{assessment_id}` | the last report for that assessment |

The agent side is driven by
[`enigma.integrations.mcp_client.MCPStdioClient`](../../src/enigma/integrations/mcp_client.py),
a dependency-free stdio JSON-RPC client you can reuse.
