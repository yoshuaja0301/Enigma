#!/usr/bin/env bash
# Install the Strix pentesting CLI (strix-agent) in an isolated environment.
# Prefers `uv` (bundles its own Python 3.12), falls back to pipx, then pip.
# Strix requires Python >= 3.12 and a running Docker daemon to actually scan.
set -euo pipefail

if command -v uv >/dev/null 2>&1; then
  echo "==> Installing strix-agent via uv (Python 3.12)"
  uv tool install strix-agent --python 3.12
elif command -v pipx >/dev/null 2>&1; then
  echo "==> Installing strix-agent via pipx"
  pipx install strix-agent
else
  echo "==> uv/pipx not found; installing strix-agent via pip"
  echo "    (requires the active Python to be >= 3.12)"
  python3 -c 'import sys; sys.exit(0 if sys.version_info >= (3,12) else 1)' \
    || { echo "ERROR: Python >= 3.12 required. Install uv (https://astral.sh/uv) and re-run." >&2; exit 1; }
  pip install strix-agent
fi

echo
strix --version || { echo "strix installed but not on PATH; add your tool bin dir to PATH." >&2; exit 1; }

echo
if command -v docker >/dev/null 2>&1 && docker info >/dev/null 2>&1; then
  echo "Docker daemon: OK — Strix can run scans."
else
  echo "NOTE: Docker daemon not reachable. Start Docker before running 'strix --target ...'."
fi

cat <<'MSG'

Next steps:
  export STRIX_LLM="openrouter/z-ai/glm-5.3"   # provider/model
  export LLM_API_KEY="your-api-key"            # from your secret manager
  strix --target https://your-app.com          # only targets you are authorized to test
MSG
