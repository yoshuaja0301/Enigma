"""Authorization validator — the authorization-first gate.

Every probe passes through here first. The order is fixed and non-negotiable:

    authorization -> scope -> policy

If any stage denies, the request is blocked and nothing is sent. OpenClaw (or
any finding source) can never bypass this gate; it only *proposes* work.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Optional

from ..core.assessment import Assessment
from .policy import Policy, PolicyGuard, policy_for_profile
from .scope import ScopeGuard


class BlockStage(str, Enum):
    NONE = "none"
    AUTHORIZATION = "authorization"
    SCOPE = "scope"
    POLICY = "policy"


@dataclass(frozen=True)
class AuthorizationResult:
    allowed: bool
    stage: BlockStage
    reason: str

    def __bool__(self) -> bool:  # pragma: no cover - trivial
        return self.allowed

    @property
    def blocked(self) -> bool:
        return not self.allowed


class AuthorizationValidator:
    """Combines authorization status, scope and policy into one gate."""

    def __init__(self, assessment: Assessment, policy: Optional[Policy] = None) -> None:
        self._assessment = assessment
        self._scope_guard = ScopeGuard(assessment.scope)
        self._policy = policy or policy_for_profile(assessment.profile)
        self._policy_guard = PolicyGuard(self._policy)

    @property
    def policy(self) -> Policy:
        return self._policy

    def authorize(self, url: str, method: str = "GET") -> AuthorizationResult:
        # 1. Authorization status must be explicit.
        if not self._assessment.authorization.is_authorized:
            return AuthorizationResult(
                False,
                BlockStage.AUTHORIZATION,
                "assessment is not marked authorized",
            )

        # 2. URL must be within the declared scope.
        scope_decision = self._scope_guard.check_url(url)
        if not scope_decision.allowed:
            return AuthorizationResult(False, BlockStage.SCOPE, scope_decision.reason)

        # 3. The action (HTTP method) must be permitted by policy.
        policy_decision = self._policy_guard.check_method(method)
        if not policy_decision.allowed:
            return AuthorizationResult(False, BlockStage.POLICY, policy_decision.reason)

        return AuthorizationResult(True, BlockStage.NONE, "authorized, in scope, within policy")
