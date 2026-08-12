"""OSSTMM taxonomy.

A pragmatic subset of the OSSTMM (Open Source Security Testing Methodology
Manual) structure — enough to place a web finding onto a channel and section and
to reason about which operational controls it touches. This is a mapping aid,
not a certification of OSSTMM compliance.
"""

from __future__ import annotations

from enum import Enum


class Channel(str, Enum):
    """OSSTMM channels."""

    HUMAN = "HUMSEC"
    PHYSICAL = "PHYSSEC"
    WIRELESS = "SPECSEC"
    TELECOMMUNICATIONS = "COMSEC/Telecommunications"
    DATA_NETWORKS = "COMSEC/Data Networks"


# Web application assessment lives in the data-networks channel.
WEB_CHANNEL = Channel.DATA_NETWORKS


class Section(str, Enum):
    ACCESS_CONTROL = "Access Control"
    CONFIDENTIALITY = "Confidentiality"
    INTEGRITY = "Integrity"
    CONFIGURATION = "Configuration & Hardening"
    INFORMATION = "Information Leakage"
