"""Normalized finding and verdict models.

A :class:`Finding` is Enigma's internal, consistent representation of a
*potential* vulnerability proposed by an AI agent (OpenClaw) or another source.
The ``check`` field names the verification procedure Enigma will run to try to
prove or disprove it.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, Optional


class Verdict(str, Enum):
    """The result of verification."""

    CONFIRMED = "CONFIRMED"
    NOT_CONFIRMED = "NOT_CONFIRMED"
    INCONCLUSIVE = "INCONCLUSIVE"


@dataclass
class Finding:
    """A normalized potential finding awaiting verification."""

    finding_id: str
    category: str = "web_application"
    type: str = "potential_vulnerability"
    title: str = ""
    description: str = ""
    confidence: float = 0.0
    target_host: Optional[str] = None
    target_path: str = "/"
    # The verification procedure key, e.g. "security_header", "reflection",
    # "http_method". If None, Enigma cannot select a procedure -> INCONCLUSIVE.
    check: Optional[str] = None
    parameters: Dict[str, Any] = field(default_factory=dict)
    source: str = "openclaw"
    raw: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "finding_id": self.finding_id,
            "category": self.category,
            "type": self.type,
            "title": self.title,
            "description": self.description,
            "confidence": self.confidence,
            "target_host": self.target_host,
            "target_path": self.target_path,
            "check": self.check,
            "parameters": self.parameters,
            "source": self.source,
        }
