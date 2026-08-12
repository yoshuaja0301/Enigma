"""Confidence helpers.

Enigma treats the AI's confidence as a *hypothesis strength*, never as proof.
These helpers keep confidence values well-formed and let the reporting layer
compare the agent's confidence against what verification actually showed — a key
research signal (does high AI confidence correlate with CONFIRMED?).
"""

from __future__ import annotations

from enum import Enum


class ConfidenceBand(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


def clamp(value: float, low: float = 0.0, high: float = 1.0) -> float:
    """Clamp a confidence value into [0, 1]."""

    try:
        value = float(value)
    except (TypeError, ValueError):
        return low
    return max(low, min(high, value))


def band(value: float) -> ConfidenceBand:
    value = clamp(value)
    if value >= 0.75:
        return ConfidenceBand.HIGH
    if value >= 0.4:
        return ConfidenceBand.MEDIUM
    return ConfidenceBand.LOW
