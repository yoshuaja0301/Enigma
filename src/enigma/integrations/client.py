"""Enigma client / connector SDK.

A thin Python wrapper over the REST API so OpenClaw-side code (or any consumer)
can talk to a running Enigma server in a few lines:

    from enigma.integrations.client import EnigmaClient

    client = EnigmaClient("http://localhost:8737", token="...")
    decision = client.validate(assessment)
    if decision["allowed"]:
        report = client.verify(assessment, findings)
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from . import http_get_json, http_post_json


class EnigmaClient:
    def __init__(self, base_url: str, token: Optional[str] = None, timeout: float = 30.0) -> None:
        self._base = base_url.rstrip("/")
        self._token = token
        self._timeout = timeout

    def health(self) -> Dict[str, Any]:
        return http_get_json(f"{self._base}/health", timeout=self._timeout)

    def validate(self, assessment: Dict[str, Any]) -> Dict[str, Any]:
        return http_post_json(
            f"{self._base}/validate",
            {"assessment": assessment},
            token=self._token,
            timeout=self._timeout,
        )

    def verify(
        self,
        assessment: Dict[str, Any],
        findings: List[Dict[str, Any]],
        callback_url: Optional[str] = None,
    ) -> Dict[str, Any]:
        payload: Dict[str, Any] = {"assessment": assessment, "findings": findings}
        if callback_url:
            payload["callback_url"] = callback_url
        return http_post_json(
            f"{self._base}/verify", payload, token=self._token, timeout=self._timeout
        )

    def get_result(self, assessment_id: str) -> Dict[str, Any]:
        return http_get_json(
            f"{self._base}/results/{assessment_id}", token=self._token, timeout=self._timeout
        )
