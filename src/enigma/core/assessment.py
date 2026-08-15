"""Assessment, authorization and scope models.

These are the *inputs* a user provides to Enigma. They describe what is being
assessed and — critically — under what authorization and within what scope.
Enigma refuses to do anything before these are validated (authorization-first).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import List, Optional, Tuple

from .target import Target


class AssessmentProfile(str, Enum):
    """How aggressively Enigma is allowed to probe.

    ``SAFE_VERIFICATION`` is the recommended default: its whole purpose is to
    *prove or disprove* a potential finding using minimal, controlled probes —
    not to perform broad exploitation.
    """

    PASSIVE = "passive"
    SAFE_VERIFICATION = "safe_verification"
    AUTHORIZED = "authorized"

    @classmethod
    def parse(cls, value: "str | AssessmentProfile") -> "AssessmentProfile":
        if isinstance(value, AssessmentProfile):
            return value
        try:
            return cls(str(value).strip().lower())
        except ValueError as exc:  # pragma: no cover - defensive
            valid = ", ".join(p.value for p in cls)
            raise ValueError(f"unknown profile {value!r}; expected one of: {valid}") from exc


class AuthorizationStatus(str, Enum):
    AUTHORIZED = "authorized"
    UNAUTHORIZED = "unauthorized"
    UNKNOWN = "unknown"

    @classmethod
    def parse(cls, value: "str | AuthorizationStatus") -> "AuthorizationStatus":
        if isinstance(value, AuthorizationStatus):
            return value
        try:
            return cls(str(value).strip().lower())
        except ValueError:
            return cls.UNKNOWN


@dataclass(frozen=True)
class Authorization:
    """Authorization metadata attached to an assessment."""

    status: AuthorizationStatus = AuthorizationStatus.UNKNOWN
    reference: Optional[str] = None
    authorized_by: Optional[str] = None

    @property
    def is_authorized(self) -> bool:
        return self.status is AuthorizationStatus.AUTHORIZED

    @classmethod
    def from_dict(cls, data: Optional[dict]) -> "Authorization":
        data = data or {}
        return cls(
            status=AuthorizationStatus.parse(data.get("status", "unknown")),
            reference=data.get("reference"),
            authorized_by=data.get("authorized_by"),
        )

    def to_dict(self) -> dict:
        return {
            "status": self.status.value,
            "reference": self.reference,
            "authorized_by": self.authorized_by,
        }


@dataclass(frozen=True)
class Scope:
    """The host/path boundary of an assessment."""

    allowed_hosts: List[str] = field(default_factory=list)
    excluded_paths: List[str] = field(default_factory=list)
    allowed_ports: List[int] = field(default_factory=list)

    @classmethod
    def from_dict(cls, data: Optional[dict]) -> "Scope":
        data = data or {}
        return cls(
            allowed_hosts=[h.lower() for h in data.get("allowed_hosts", [])],
            excluded_paths=list(data.get("excluded_paths", [])),
            allowed_ports=list(data.get("allowed_ports", [])),
        )

    def to_dict(self) -> dict:
        return {
            "allowed_hosts": self.allowed_hosts,
            "excluded_paths": self.excluded_paths,
            "allowed_ports": self.allowed_ports,
        }


@dataclass(frozen=True)
class Assessment:
    """A complete, validated-by-construction assessment configuration."""

    assessment_id: str
    target: Target
    authorization: Authorization
    scope: Scope
    profile: AssessmentProfile = AssessmentProfile.SAFE_VERIFICATION
    methodology: str = "OSSTMM"
    # Testing instruments declared for this assessment (e.g. nmap, whatweb,
    # nuclei, zap). They record *methodological* module coverage; they are not
    # evidence — anything they find still goes through Enigma's verification.
    instruments: Tuple[str, ...] = ()

    @classmethod
    def from_dict(cls, data: dict) -> "Assessment":
        if "assessment_id" not in data:
            raise ValueError("assessment configuration requires 'assessment_id'")
        if "target" not in data:
            raise ValueError("assessment configuration requires 'target'")
        return cls(
            assessment_id=str(data["assessment_id"]),
            target=Target.from_dict(data["target"]),
            authorization=Authorization.from_dict(data.get("authorization")),
            scope=Scope.from_dict(data.get("scope")),
            profile=AssessmentProfile.parse(data.get("profile", "safe_verification")),
            methodology=str(data.get("methodology", "OSSTMM")),
            instruments=tuple(str(i) for i in data.get("instruments", ())),
        )

    def to_dict(self) -> dict:
        return {
            "assessment_id": self.assessment_id,
            "target": self.target.to_dict(),
            "authorization": self.authorization.to_dict(),
            "scope": self.scope.to_dict(),
            "profile": self.profile.value,
            "methodology": self.methodology,
            "instruments": list(self.instruments),
        }
