"""Model Context Protocol (MCP) server for Enigma.

Exposes Enigma to AI agents (such as OpenClaw) as MCP tools over stdio using
JSON-RPC 2.0. No third-party dependency is required — the minimal subset of the
protocol needed for tool use is implemented directly:

    initialize            -> server info + capabilities
    notifications/initialized (notification, no response)
    tools/list            -> the Enigma tool catalogue
    tools/call            -> dispatch a tool and return its JSON result

Tools
-----
* ``validate_scope``   — run the authorization/scope/policy gate (no probes)
* ``verify_findings``  — verify OpenClaw findings and return a report
* ``get_result``       — fetch a previously computed report by assessment id

Run it with ``enigma mcp`` and register that command as an MCP server on the
agent side.
"""

from __future__ import annotations

import json
import sys
from typing import Any, Dict, Optional

from ..service import EnigmaService, ServerScopeError

PROTOCOL_VERSION = "2024-11-05"
SERVER_INFO = {"name": "enigma", "version": "0.1.0"}

_ASSESSMENT_SCHEMA = {
    "type": "object",
    "description": "Enigma assessment configuration (target, authorization, scope, profile).",
}

TOOLS = [
    {
        "name": "validate_scope",
        "description": "Run only the authorization/scope/policy gate for an assessment. Sends no probes. "
        "Returns whether the target is allowed and, if not, which stage blocked it.",
        "inputSchema": {
            "type": "object",
            "properties": {"assessment": _ASSESSMENT_SCHEMA},
            "required": ["assessment"],
        },
    },
    {
        "name": "verify_findings",
        "description": "Verify a batch of potential findings for an assessment using controlled, "
        "non-destructive probes. Returns a report with CONFIRMED/NOT_CONFIRMED/INCONCLUSIVE "
        "verdicts, reproducibility, sanitized evidence ids and OSSTMM mapping.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "assessment": _ASSESSMENT_SCHEMA,
                "findings": {
                    "type": "array",
                    "description": "List of potential findings (OpenClaw output).",
                    "items": {"type": "object"},
                },
            },
            "required": ["assessment", "findings"],
        },
    },
    {
        "name": "get_result",
        "description": "Fetch the most recent verification report for an assessment id.",
        "inputSchema": {
            "type": "object",
            "properties": {"assessment_id": {"type": "string"}},
            "required": ["assessment_id"],
        },
    },
]


class EnigmaMcpServer:
    def __init__(self, service: Optional[EnigmaService] = None) -> None:
        self._service = service or EnigmaService()

    # ------------------------------------------------------------------ #
    def handle_message(self, message: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Handle a single JSON-RPC message. Returns a response, or None for notifications."""

        method = message.get("method")
        msg_id = message.get("id")
        params = message.get("params") or {}

        # Notifications have no id and expect no response.
        if msg_id is None and method and method.startswith("notifications/"):
            return None

        try:
            if method == "initialize":
                return _ok(msg_id, self._initialize())
            if method == "tools/list":
                return _ok(msg_id, {"tools": TOOLS})
            if method == "tools/call":
                return _ok(msg_id, self._call_tool(params))
            if method == "ping":
                return _ok(msg_id, {})
            return _err(msg_id, -32601, f"method not found: {method}")
        except _ToolError as exc:
            return _ok(msg_id, _tool_error(str(exc)))
        except Exception as exc:  # pragma: no cover - defensive
            return _err(msg_id, -32603, f"internal error: {exc}")

    # ------------------------------------------------------------------ #
    def _initialize(self) -> Dict[str, Any]:
        return {
            "protocolVersion": PROTOCOL_VERSION,
            "serverInfo": SERVER_INFO,
            "capabilities": {"tools": {"listChanged": False}},
        }

    def _call_tool(self, params: Dict[str, Any]) -> Dict[str, Any]:
        name = params.get("name")
        arguments = params.get("arguments") or {}

        try:
            if name == "validate_scope":
                result = self._service.validate(_require(arguments, "assessment"))
            elif name == "verify_findings":
                result = self._service.verify(
                    _require(arguments, "assessment"), arguments.get("findings", [])
                )
            elif name == "get_result":
                result = self._service.get_result(_require(arguments, "assessment_id"))
                if result is None:
                    raise _ToolError(
                        f"no result for assessment_id {arguments.get('assessment_id')!r}"
                    )
            else:
                raise _ToolError(f"unknown tool: {name}")
        except (ServerScopeError, ValueError, KeyError) as exc:
            raise _ToolError(str(exc))

        return _tool_result(result)

    # ------------------------------------------------------------------ #
    def serve_stdio(self, stdin=None, stdout=None) -> None:  # pragma: no cover - loop
        stdin = stdin or sys.stdin
        stdout = stdout or sys.stdout
        for line in stdin:
            line = line.strip()
            if not line:
                continue
            try:
                message = json.loads(line)
            except json.JSONDecodeError:
                continue
            response = self.handle_message(message)
            if response is not None:
                stdout.write(json.dumps(response) + "\n")
                stdout.flush()


# --------------------------------------------------------------------------- #
class _ToolError(Exception):
    pass


def _require(arguments: Dict[str, Any], key: str) -> Any:
    if key not in arguments:
        raise _ToolError(f"missing required argument: {key}")
    return arguments[key]


def _tool_result(result: Any) -> Dict[str, Any]:
    return {"content": [{"type": "text", "text": json.dumps(result, ensure_ascii=False)}], "isError": False}


def _tool_error(message: str) -> Dict[str, Any]:
    return {"content": [{"type": "text", "text": message}], "isError": True}


def _ok(msg_id: Any, result: Dict[str, Any]) -> Dict[str, Any]:
    return {"jsonrpc": "2.0", "id": msg_id, "result": result}


def _err(msg_id: Any, code: int, message: str) -> Dict[str, Any]:
    return {"jsonrpc": "2.0", "id": msg_id, "error": {"code": code, "message": message}}
