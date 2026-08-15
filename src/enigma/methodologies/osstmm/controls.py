"""OSSTMM operational controls.

The OSSTMM defines ten operational controls, split into Class A (interactive)
and Class B (process). Enigma tags each mapped finding with the controls it is
most relevant to, which supports later analysis of coverage.
"""

from __future__ import annotations

from enum import Enum


class Control(str, Enum):
    # Class A — interactive controls
    AUTHENTICATION = "Authentication"
    INDEMNIFICATION = "Indemnification"
    RESILIENCE = "Resilience"
    SUBJUGATION = "Subjugation"
    CONTINUITY = "Continuity"
    # Class B — process controls
    NON_REPUDIATION = "Non-Repudiation"
    CONFIDENTIALITY = "Confidentiality"
    PRIVACY = "Privacy"
    INTEGRITY = "Integrity"
    ALARM = "Alarm"


CLASS_A = frozenset(
    {
        Control.AUTHENTICATION,
        Control.INDEMNIFICATION,
        Control.RESILIENCE,
        Control.SUBJUGATION,
        Control.CONTINUITY,
    }
)

CLASS_B = frozenset(
    {
        Control.NON_REPUDIATION,
        Control.CONFIDENTIALITY,
        Control.PRIVACY,
        Control.INTEGRITY,
        Control.ALARM,
    }
)
