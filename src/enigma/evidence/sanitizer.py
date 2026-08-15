"""Evidence sanitizer.

Evidence must be reviewable without leaking secrets. This sanitizer redacts
credentials, tokens, session material and obvious PII from headers, URLs and
bodies before anything is stored. It errs on the side of over-redaction — a
redacted-but-safe artifact is always preferable to a leaked secret.
"""

from __future__ import annotations

import re
from typing import Any, Dict

REDACTION = "[REDACTED]"

# Header names whose values are always sensitive.
SENSITIVE_HEADERS = frozenset(
    {
        "authorization",
        "proxy-authorization",
        "cookie",
        "set-cookie",
        "x-api-key",
        "api-key",
        "x-auth-token",
        "x-csrf-token",
        "x-session-token",
        "x-access-token",
    }
)

# Query/body parameter names that carry secrets.
SENSITIVE_PARAMS = frozenset(
    {"password", "passwd", "pwd", "token", "secret", "api_key", "apikey", "access_token", "session"}
)

_PATTERNS = (
    # Bearer tokens.
    re.compile(r"(?i)bearer\s+[A-Za-z0-9._\-]+"),
    # JWT-like tokens (three base64url segments).
    re.compile(r"\beyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+"),
    # sensitive params in query strings / form bodies: name=value
    re.compile(
        r"(?i)\b(" + "|".join(sorted(SENSITIVE_PARAMS)) + r")=([^&\s\"']+)"
    ),
    # Email addresses (PII).
    re.compile(r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b"),
)


class EvidenceSanitizer:
    """Redacts sensitive material from strings, headers and nested structures."""

    def sanitize_text(self, text: str) -> str:
        if not text:
            return text
        result = text
        for pattern in _PATTERNS:
            if pattern.groups == 2:
                # keep the param name, redact only the value
                result = pattern.sub(lambda m: f"{m.group(1)}={REDACTION}", result)
            else:
                result = pattern.sub(REDACTION, result)
        return result

    def sanitize_headers(self, headers: Dict[str, str]) -> Dict[str, str]:
        clean: Dict[str, str] = {}
        for name, value in headers.items():
            if name.lower() in SENSITIVE_HEADERS:
                clean[name] = REDACTION
            else:
                clean[name] = self.sanitize_text(str(value))
        return clean

    def sanitize_url(self, url: str) -> str:
        return self.sanitize_text(url)

    def sanitize(self, obj: Any) -> Any:
        """Recursively sanitize a JSON-like structure."""

        if isinstance(obj, str):
            return self.sanitize_text(obj)
        if isinstance(obj, dict):
            out: Dict[str, Any] = {}
            for key, value in obj.items():
                if str(key).lower() in SENSITIVE_HEADERS or str(key).lower() in SENSITIVE_PARAMS:
                    out[key] = REDACTION
                else:
                    out[key] = self.sanitize(value)
            return out
        if isinstance(obj, (list, tuple)):
            return [self.sanitize(v) for v in obj]
        return obj
