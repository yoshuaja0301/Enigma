"""Authorization, scope and policy guards (the authorization-first gate)."""

from .policy import (
    STATE_CHANGING_METHODS,
    Policy,
    PolicyDecision,
    PolicyGuard,
    policy_for_profile,
)
from .scope import ScopeDecision, ScopeGuard
from .validator import AuthorizationResult, AuthorizationValidator, BlockStage

__all__ = [
    "ScopeGuard",
    "ScopeDecision",
    "Policy",
    "PolicyGuard",
    "PolicyDecision",
    "policy_for_profile",
    "STATE_CHANGING_METHODS",
    "AuthorizationValidator",
    "AuthorizationResult",
    "BlockStage",
]
