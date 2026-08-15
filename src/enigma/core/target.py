"""Target model.

A :class:`Target` represents the website or application under assessment. It is
intentionally thin: it only parses a URL into its components so the rest of the
framework can reason about host, scheme, port and path without re-parsing.
"""

from __future__ import annotations

from dataclasses import dataclass
from urllib.parse import urlparse

_DEFAULT_PORTS = {"http": 80, "https": 443}


@dataclass(frozen=True)
class Target:
    """A single authorized assessment target."""

    url: str

    def __post_init__(self) -> None:
        parsed = urlparse(self.url)
        if not parsed.scheme or not parsed.hostname:
            raise ValueError(f"target url must be absolute (scheme + host): {self.url!r}")

    @property
    def scheme(self) -> str:
        return urlparse(self.url).scheme.lower()

    @property
    def host(self) -> str:
        host = urlparse(self.url).hostname
        assert host is not None  # guarded in __post_init__
        return host.lower()

    @property
    def port(self) -> int:
        parsed = urlparse(self.url)
        if parsed.port is not None:
            return parsed.port
        return _DEFAULT_PORTS.get(parsed.scheme.lower(), 0)

    @property
    def path(self) -> str:
        return urlparse(self.url).path or "/"

    def base_url(self) -> str:
        parsed = urlparse(self.url)
        netloc = parsed.hostname or ""
        if parsed.port is not None:
            netloc = f"{netloc}:{parsed.port}"
        return f"{parsed.scheme}://{netloc}"

    @classmethod
    def from_dict(cls, data: dict) -> "Target":
        if isinstance(data, str):
            return cls(url=data)
        return cls(url=data["url"])

    def to_dict(self) -> dict:
        return {"url": self.url, "host": self.host, "port": self.port}
