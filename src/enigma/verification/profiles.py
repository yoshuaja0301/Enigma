"""Verification profiles.

A verification profile ties together the policy (what may be sent) and the
repeat count (how many times a probe is repeated to assess reproducibility).
Profiles are derived from the assessment profile so a single ``profile`` field
in the assessment config drives the whole safety envelope.
"""

from __future__ import annotations

from dataclasses import dataclass

from ..authorization.policy import Policy, policy_for_profile
from ..core.assessment import AssessmentProfile


@dataclass(frozen=True)
class VerificationProfile:
    name: str
    policy: Policy
    repeat_count: int  # how many times to repeat a probe for reproducibility

    @property
    def max_probes_per_finding(self) -> int:
        return self.policy.max_probes_per_finding


_REPEAT_COUNTS = {
    AssessmentProfile.PASSIVE: 1,
    AssessmentProfile.SAFE_VERIFICATION: 2,
    AssessmentProfile.AUTHORIZED: 3,
}


def verification_profile_for(profile: AssessmentProfile) -> VerificationProfile:
    return VerificationProfile(
        name=profile.value,
        policy=policy_for_profile(profile),
        repeat_count=_REPEAT_COUNTS[profile],
    )
