"""OSSTMM mapping: taxonomy, operational controls and the mapper."""

from .controls import CLASS_A, CLASS_B, Control
from .mapper import OsstmmMapper
from .taxonomy import WEB_CHANNEL, Channel, Section

__all__ = [
    "OsstmmMapper",
    "Channel",
    "Section",
    "WEB_CHANNEL",
    "Control",
    "CLASS_A",
    "CLASS_B",
]
