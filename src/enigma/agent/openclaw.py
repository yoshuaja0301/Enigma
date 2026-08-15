"""OpenClaw agent adapters.

OpenClaw is the *AI assessor*: it proposes potential findings. Enigma never lets
OpenClaw decide what is confirmed or what is in scope — it only consumes
proposals through the :class:`OpenClawAdapter` interface (one method,
``get_findings``).

Adapters provided:

* :class:`StaticOpenClawAdapter`   — fixed list / file (replay, tests, offline).
* :class:`CallableOpenClawAdapter` — any LLM/function; you pass a completion
  callable ``(prompt) -> text`` and Enigma builds the prompt + parses the output.
* :class:`HttpOpenClawAdapter`     — an OpenClaw HTTP service (POST target,
  receive findings JSON).

A real integration is usually just picking one of these and wiring your model or
endpoint. Whatever the transport, the adapter returns raw finding dicts in the
schema :class:`enigma.findings.normalizer.FindingNormalizer` understands.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Callable, Dict, Iterable, List, Optional, Protocol, Union, runtime_checkable
from urllib import request as _request
from urllib.error import HTTPError, URLError

from ..core.assessment import Assessment
from .prompt import build_openclaw_prompt, build_openclaw_request, coerce_findings, parse_openclaw_findings


@runtime_checkable
class OpenClawAdapter(Protocol):
    """Interface Enigma expects from any AI finding source."""

    def get_findings(self, assessment: Assessment) -> List[Dict[str, Any]]:
        """Return a list of raw (un-normalized) potential findings."""
        ...


class StaticOpenClawAdapter:
    """An adapter backed by a fixed list of raw findings (replay / tests / offline)."""

    def __init__(self, findings: Iterable[Dict[str, Any]]) -> None:
        self._findings = [dict(f) for f in findings]

    def get_findings(self, assessment: Assessment) -> List[Dict[str, Any]]:  # noqa: ARG002
        return [dict(f) for f in self._findings]

    @classmethod
    def from_file(cls, source: Union[str, Path]) -> "StaticOpenClawAdapter":
        path = Path(source)
        with path.open("r", encoding="utf-8") as handle:
            data = json.load(handle)
        return cls(coerce_findings(data))

    @classmethod
    def from_data(cls, data: Any) -> "StaticOpenClawAdapter":
        return cls(coerce_findings(data))


class CallableOpenClawAdapter:
    """Drive OpenClaw as an LLM (or any function).

    ``completion`` is any callable that takes a prompt string and returns the
    model's text. Wire your provider of choice, e.g.::

        def complete(prompt: str) -> str:
            return anthropic_client.messages.create(
                model="claude-...", max_tokens=2000,
                messages=[{"role": "user", "content": prompt}],
            ).content[0].text

        adapter = CallableOpenClawAdapter(complete)

    Enigma builds the prompt (target + supported checks) and parses the model's
    JSON output — tolerating a surrounding code fence.
    """

    def __init__(
        self,
        completion: Callable[[str], Any],
        prompt_builder: Callable[[Assessment], str] = build_openclaw_prompt,
    ) -> None:
        self._completion = completion
        self._prompt_builder = prompt_builder

    def get_findings(self, assessment: Assessment) -> List[Dict[str, Any]]:
        prompt = self._prompt_builder(assessment)
        output = self._completion(prompt)
        return parse_openclaw_findings(output)


class HttpOpenClawAdapter:
    """Call an OpenClaw HTTP service.

    POSTs a JSON description of the target (see
    :func:`enigma.agent.prompt.build_openclaw_request`) and expects a findings
    array — either bare or wrapped in ``{"findings": [...]}``.
    """

    def __init__(
        self,
        endpoint: str,
        api_key: Optional[str] = None,
        timeout: float = 60.0,
        request_builder: Callable[[Assessment], Dict[str, Any]] = build_openclaw_request,
    ) -> None:
        self._endpoint = endpoint
        self._api_key = api_key
        self._timeout = timeout
        self._request_builder = request_builder

    def get_findings(self, assessment: Assessment) -> List[Dict[str, Any]]:
        payload = self._request_builder(assessment)
        response = self._post(self._endpoint, payload)
        return parse_openclaw_findings(response)

    def _post(self, url: str, data: Dict[str, Any]) -> Any:
        body = json.dumps(data).encode("utf-8")
        headers = {"Content-Type": "application/json", "Accept": "application/json"}
        if self._api_key:
            headers["Authorization"] = f"Bearer {self._api_key}"
        req = _request.Request(url, data=body, headers=headers, method="POST")
        try:
            with _request.urlopen(req, timeout=self._timeout) as resp:
                return json.loads(resp.read().decode("utf-8", errors="replace"))
        except HTTPError as exc:
            detail = exc.read().decode("utf-8", errors="replace")
            raise RuntimeError(f"OpenClaw HTTP {exc.code}: {detail}") from exc
        except (URLError, TimeoutError, OSError) as exc:
            raise RuntimeError(f"OpenClaw request failed: {exc}") from exc
