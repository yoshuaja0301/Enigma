"""A minimal MCP stdio client.

The counterpart to :class:`enigma.integrations.client.EnigmaClient` (REST) for
the MCP surface. It launches an MCP server command (e.g. ``enigma mcp``), speaks
JSON-RPC 2.0 over its stdio, and exposes ``initialize`` / ``list_tools`` /
``call_tool``. Useful for driving Enigma the way an AI agent (OpenClaw) would,
and for automated end-to-end tests.

Dependency-free; standard library only.
"""

from __future__ import annotations

import json
import subprocess
from typing import Any, Dict, List, Optional, Sequence


class MCPError(RuntimeError):
    pass


class MCPStdioClient:
    def __init__(
        self,
        command: Sequence[str],
        env: Optional[Dict[str, str]] = None,
        cwd: Optional[str] = None,
    ) -> None:
        self._command = list(command)
        self._env = env
        self._cwd = cwd
        self._proc: Optional[subprocess.Popen] = None
        self._id = 0
        self.server_info: Dict[str, Any] = {}

    # -- lifecycle ------------------------------------------------------ #
    def start(self) -> "MCPStdioClient":
        self._proc = subprocess.Popen(
            self._command,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
            bufsize=1,
            env=self._env,
            cwd=self._cwd,
        )
        return self

    def __enter__(self) -> "MCPStdioClient":
        self.start()
        self.initialize()
        return self

    def __exit__(self, *exc) -> None:
        self.close()

    def close(self) -> None:
        proc, self._proc = self._proc, None
        if proc is None:
            return
        try:
            if proc.stdin:
                proc.stdin.close()
        except OSError:
            pass
        try:
            proc.terminate()
            proc.wait(timeout=5)
        except Exception:  # pragma: no cover - best effort
            try:
                proc.kill()
            except Exception:
                pass

    # -- JSON-RPC ------------------------------------------------------- #
    def _send(self, message: Dict[str, Any]) -> None:
        if not self._proc or not self._proc.stdin:
            raise MCPError("client not started")
        self._proc.stdin.write(json.dumps(message) + "\n")
        self._proc.stdin.flush()

    def _read_response(self, expect_id: int) -> Dict[str, Any]:
        if not self._proc or not self._proc.stdout:
            raise MCPError("client not started")
        while True:
            line = self._proc.stdout.readline()
            if line == "":
                raise MCPError("MCP server closed the connection unexpectedly")
            line = line.strip()
            if not line:
                continue
            message = json.loads(line)
            if message.get("id") == expect_id:
                return message

    def _request(self, method: str, params: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        self._id += 1
        rid = self._id
        self._send({"jsonrpc": "2.0", "id": rid, "method": method, "params": params or {}})
        response = self._read_response(rid)
        if "error" in response:
            raise MCPError(f"{method} failed: {response['error']}")
        return response.get("result", {})

    def _notify(self, method: str, params: Optional[Dict[str, Any]] = None) -> None:
        self._send({"jsonrpc": "2.0", "method": method, "params": params or {}})

    # -- MCP methods ---------------------------------------------------- #
    def initialize(self) -> Dict[str, Any]:
        self.server_info = self._request("initialize")
        self._notify("notifications/initialized")
        return self.server_info

    def list_tools(self) -> List[Dict[str, Any]]:
        return self._request("tools/list").get("tools", [])

    def call_tool(self, name: str, arguments: Dict[str, Any]) -> Any:
        result = self._request("tools/call", {"name": name, "arguments": arguments})
        content = result.get("content", [])
        text = content[0]["text"] if content else "{}"
        if result.get("isError"):
            raise MCPError(f"tool {name!r} error: {text}")
        try:
            return json.loads(text)
        except json.JSONDecodeError:
            return {"text": text}
