"""Policy guard.

Where the scope guard answers *"may I touch this URL?"*, the policy guard
answers *"may I perform this kind of action?"* — which HTTP methods are allowed,
whether state-changing requests are permitted, and how many probes/second the
profile tolerates. Policies are derived from the assessment profile.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import List

from ..core.assessment import AssessmentProfile

# Methods that can change server state. Safe verification never uses these.
STATE_CHANGING_METHODS = frozenset({"POST", "PUT", "PATCH", "DELETE"})


@dataclass(frozen=True)
class Policy:
    """Safety limits enforced during verification."""

    allowed_methods: List[str] = field(default_factory=lambda: ["GET", "HEAD"])
    allow_state_changing: bool = False
    max_probes_per_finding: int = 5
    request_delay_seconds: float = 0.0
    max_body_bytes: int = 262_144  # 256 KiB read cap on responses

    def allows_method(self, method: str) -> bool:
        method = method.upper()
        if method in STATE_CHANGING_METHODS and not self.allow_state_changing:
            return False
        return method in {m.upper() for m in self.allowed_methods}


# Profile -> Policy. Passive is read-only with a single observation; safe
# verification permits a handful of controlled read probes; authorized allows a
# broader, still non-destructive-by-default set.
_PROFILE_POLICIES = {
    AssessmentProfile.PASSIVE: Policy(
        allowed_methods=["GET", "HEAD"],
        allow_state_changing=False,
        max_probes_per_finding=1,
        request_delay_seconds=0.0,
    ),
    AssessmentProfile.SAFE_VERIFICATION: Policy(
        allowed_methods=["GET", "HEAD", "OPTIONS"],
        allow_state_changing=False,
        max_probes_per_finding=5,
        request_delay_seconds=0.0,
    ),
    AssessmentProfile.AUTHORIZED: Policy(
        allowed_methods=["GET", "HEAD", "OPTIONS"],
        allow_state_changing=False,
        max_probes_per_finding=10,
        request_delay_seconds=0.0,
    ),
}


def policy_for_profile(profile: AssessmentProfile) -> Policy:
    return _PROFILE_POLICIES[profile]


@dataclass(frozen=True)
class PolicyDecision:
    allowed: bool
    reason: str

    def __bool__(self) -> bool:  # pragma: no cover - trivial
        return self.allowed


class PolicyGuard:
    """Enforces a :class:`Policy` for individual requests."""

    def __init__(self, policy: Policy) -> None:
        self._policy = policy

    @property
    def policy(self) -> Policy:
        return self._policy

    def check_method(self, method: str) -> PolicyDecision:
        if not self._policy.allows_method(method):
            return PolicyDecision(False, f"method '{method.upper()}' not permitted by policy")
        return PolicyDecision(True, "method permitted")
