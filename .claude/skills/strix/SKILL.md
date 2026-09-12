---
name: strix
description: >-
  Run Strix, the open-source autonomous AI penetration-testing agent
  (usestrix/strix, PyPI `strix-agent`), to perform recon, exploitation, and
  proof-of-concept vulnerability validation against a target you are authorized
  to test. Use this skill whenever the user asks to pentest, security-scan, find
  or validate web/app/API vulnerabilities, run OWASP Top 10 testing, do dynamic
  or static security analysis, or mentions "Strix" / "strix". Complements the
  Enigma evidence-based verification framework: Strix discovers and exploits,
  Enigma verifies. Only run against assets the user owns or has explicit written
  authorization to test.
license: MIT (Strix is MIT-licensed; see https://github.com/usestrix/strix)
---

# Strix — Autonomous AI Penetration Testing

Strix is an open-source AI agent that acts like a security researcher: it runs
reconnaissance, actively exploits findings, and validates them with real
proof-of-concept exploits (not static heuristics). It orchestrates multiple
agents in an isolated Docker sandbox and produces a run report you can open in a
local viewer.

This skill is cross-compatible with the open Agent Skills standard — it works
unchanged in OpenClaw, Claude Code, and other SKILL.md-based agents.

## ⚠️ Authorization first (non-negotiable)

Strix launches real attacks. Before running it against any target:

- Confirm the user **owns the target or has explicit written authorization**
  (scope, rules of engagement, time window) to test it.
- Never point Strix at third-party systems, production you don't control, or
  arbitrary internet hosts on a hunch.
- For untrusted source repos/URLs, prefer scoped local analysis over live
  exploitation.

If authorization is unclear, ask the user to confirm scope before scanning.

## Prerequisites

- **Docker daemon running** — the first run pulls a sandbox image; every scan
  executes inside that container. `docker info` must succeed.
- **Python ≥ 3.12** — required by `strix-agent`.
- **An LLM API key** from a supported provider (OpenAI, Anthropic, Google,
  OpenRouter, DeepSeek, …).

## Install

Preferred (isolated, no venv juggling — installs its own Python 3.12):

```bash
uv tool install strix-agent          # if `uv` is available
```

Alternatives:

```bash
pipx install strix-agent             # isolated via pipx
pip install strix-agent              # into a Python >=3.12 environment
curl -sSL https://strix.ai/install | bash   # upstream one-liner (review before piping to bash)
```

Verify:

```bash
strix --version        # -> strix 1.6.2 (or newer)
strix --help
```

Upgrade later with `strix --update` (prints the right upgrade command for
pip/pipx/uv installs; self-updates the standalone binary).

## Configure

```bash
export STRIX_LLM="openrouter/z-ai/glm-5.3"   # provider/model string
export LLM_API_KEY="your-api-key"            # never hard-code or commit this
# optional:
export LLM_API_BASE="https://your-api-base"  # custom/self-hosted endpoint
export POSTMAN_API_KEY="..."                 # only for postman:// targets
```

Do **not** write keys into the repo, the skill, or run reports. Read them from
the environment or the user's secret manager.

## Run

Targets can be a URL, a git repo, a local directory, a domain, an IP, an API
spec (OpenAPI/Swagger `.json`/`.yaml` or a Postman collection), or
`postman://<uuid>`. `-t/--target` is repeatable for multi-target (white-box)
scans.

```bash
# Web application
strix --target https://your-app.com

# Local source code
strix --target ./app-directory

# Git repository
strix --target https://github.com/org/repo

# White-box: source + deployed app together
strix --target ./app-directory --target https://staging.your-app.com

# API testing with a spec
strix --target ./openapi.yaml --target https://api.your-app.com

# Focused / authenticated testing
strix --target https://your-app.com --instruction "Focus on IDOR and XSS"
strix --target https://your-app.com --instruction "Use creds admin:pass123 for authenticated testing"

# Many targets from a file (one per line)
strix --target-list ./targets.txt

# Headless (CI/CD — no interactive TUI)
strix -n --target https://your-app.com
```

Useful controls:

| Flag | Purpose |
|------|---------|
| `-m {quick,standard,deep}` | Scan depth / thoroughness |
| `--scope-mode {auto,diff,full}` + `--diff-base REF` | Limit to changed code (great for PR/CI gating) |
| `--max-budget USD` | Hard cap on LLM spend; stops cleanly when hit |
| `--max-turns N` | Per-agent turn limit (default 500) |
| `--workspace-file PATH[:DEST]` | Drop extra files (wordlists, specs) into the sandbox |
| `--instruction-file PATH` | Long custom instructions from a file |
| `--resume RUN_NAME` | Resume a prior run under `./strix_runs/` |
| `--mcp-config` / `--mcp-server` / `--mcp-exclude` | Wire in MCP tools |

## Review results

```bash
strix view                 # open the latest run in the local dashboard
strix view my-run-name     # open a specific run
strix view --host 0.0.0.0 --port 8080 --no-open   # serve headless (e.g. remote box)
```

Runs are stored under `./strix_runs/`. **Treat reports as sensitive** — they can
contain exploited payloads, credentials, and PII. Don't commit `strix_runs/` to
git (add it to `.gitignore`).

## Cloud (optional)

```bash
strix cloud login
strix cloud scans start --source . --yes --wait
strix cloud                 # list cloud resources
```

## Using Strix with Enigma

Enigma is an evidence-based vulnerability *verification* framework. A natural
flow:

1. **Discover & exploit** with Strix (`strix --target ...`) → get PoC-backed
   findings under `./strix_runs/`.
2. **Verify & document** the surviving findings with Enigma's workflow so each
   reported issue carries reproducible evidence.

Run Strix in headless mode with `--scope-mode diff --diff-base origin/main` to
gate pull requests on newly introduced vulnerabilities.

## Troubleshooting

- **`docker` errors / hangs on first run** → Docker daemon not running or image
  pull blocked. Start Docker; confirm with `docker info`.
- **`No matching distribution` / install fails** → Python < 3.12. Use
  `uv tool install strix-agent` or a 3.12+ interpreter.
- **Auth / 401 from the model** → check `STRIX_LLM`, `LLM_API_KEY`, and
  `LLM_API_BASE`.
- **Costs run away** → always set `--max-budget` for autonomous runs.
