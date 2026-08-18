"""OSSTMM 3 test phases, the 17 modules, and instrument (tool) mapping.

Where :mod:`rav` answers *"how secure is it"*, this module answers *"was the
methodology actually followed"* — the checklist question. It encodes:

* the four OSSTMM 3 **test phases** (A Induction, B Interaction, C Inquest,
  D Intervention) and the **17 modules** distributed across them;
* which **instrument** (Nmap, WhatWeb, Nuclei, OWASP ZAP, Enigma itself) exercises
  which modules;
* a **coverage calculator** that reports, per phase, which modules were covered
  and which were not — with attribution, so a reader can see *what* covered a
  module rather than taking the claim on faith.

Instruments are *finders*: they observe and enumerate. Enigma remains the
*verifier* — an instrument's output enters through the same adapter seam as
OpenClaw and is still subject to verification before it can affect a verdict or
the RAV. Declaring an instrument therefore records **methodological coverage**,
never evidence on its own.

Honest limits, stated rather than papered over:

* **Phase D (Intervention)** — quarantine, privileges, survivability and
  alert/log review — is *not* covered by these instruments. It needs intrusive
  testing or internal access, which is outside Enigma's non-destructive remit.
* Phase A modules 2 (Logistics) and 3 (Active Detection Verification) are also
  uncovered by this instrument set.

Reference
---------
ISECOM, *OSSTMM 3: The Open Source Security Testing Methodology Manual*,
Chapter 4 ("Operational Security Testing"), the Four Point Process and the
17 modules of the test phases.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, Iterable, List, Optional, Sequence, Set, Tuple


class Phase(str, Enum):
    """OSSTMM 3 test phases."""

    A = "A"  # Induction
    B = "B"  # Interaction
    C = "C"  # Inquest
    D = "D"  # Intervention


PHASE_NAMES: Dict[Phase, str] = {
    Phase.A: "Induction",
    Phase.B: "Interaction",
    Phase.C: "Inquest",
    Phase.D: "Intervention",
}


@dataclass(frozen=True)
class Module:
    number: int
    name: str
    phase: Phase


# The 17 modules of OSSTMM 3, in order.
MODULES: Dict[int, Module] = {
    m.number: m
    for m in (
        # Phase A — Induction
        Module(1, "Posture Review", Phase.A),
        Module(2, "Logistics", Phase.A),
        Module(3, "Active Detection Verification", Phase.A),
        # Phase B — Interaction
        Module(4, "Visibility Audit", Phase.B),
        Module(5, "Access Verification", Phase.B),
        Module(6, "Trust Verification", Phase.B),
        Module(7, "Controls Verification", Phase.B),
        # Phase C — Inquest
        Module(8, "Process Verification", Phase.C),
        Module(9, "Configuration Verification", Phase.C),
        Module(10, "Property Validation", Phase.C),
        Module(11, "Segregation Review", Phase.C),
        Module(12, "Exposure Verification", Phase.C),
        Module(13, "Competitive Intelligence Scouting", Phase.C),
        # Phase D — Intervention
        Module(14, "Quarantine Verification", Phase.D),
        Module(15, "Privileges Audit", Phase.D),
        Module(16, "Survivability Validation", Phase.D),
        Module(17, "Alert and Log Review", Phase.D),
    )
}


def modules_in_phase(phase: Phase) -> List[Module]:
    return [m for m in MODULES.values() if m.phase is phase]


# --------------------------------------------------------------------------- #
# Instruments (testing tools) and the modules they exercise.
# --------------------------------------------------------------------------- #
@dataclass(frozen=True)
class Instrument:
    key: str
    name: str
    role: str
    modules: Tuple[int, ...]

    @property
    def phases(self) -> List[Phase]:
        seen: List[Phase] = []
        for number in self.modules:
            phase = MODULES[number].phase
            if phase not in seen:
                seen.append(phase)
        return seen

    def to_dict(self) -> dict:
        return {
            "key": self.key,
            "name": self.name,
            "role": self.role,
            "modules": [
                {"number": n, "name": MODULES[n].name, "phase": MODULES[n].phase.value}
                for n in self.modules
            ],
            "phases": [p.value for p in self.phases],
        }


INSTRUMENTS: Dict[str, Instrument] = {
    "nmap": Instrument(
        key="nmap",
        name="Nmap",
        role="Port and service scanning — supports the visibility audit and access verification.",
        modules=(4, 5),
    ),
    "whatweb": Instrument(
        key="whatweb",
        name="WhatWeb",
        role="Web technology identification — supports configuration and exposure verification.",
        modules=(9, 12),
    ),
    "nuclei": Instrument(
        key="nuclei",
        name="Nuclei",
        role="Template-based vulnerability scanning — supports exposure verification.",
        modules=(12,),
    ),
    "zap": Instrument(
        key="zap",
        name="OWASP ZAP",
        role="Web application security scanning — supports controls and exposure verification.",
        modules=(7, 12),
    ),
    "enigma": Instrument(
        key="enigma",
        name="Enigma",
        role=(
            "Authorization/scope definition (posture review) plus evidence-based "
            "verification of proposed findings."
        ),
        # Module 1 is covered by the authorization-first gate: scope, rules and
        # permitted actions are defined and enforced before any test runs.
        # The remaining modules come from whichever checks actually ran.
        modules=(1,),
    ),
}

# Aliases so a methodology section can name a tool naturally.
_INSTRUMENT_ALIASES = {
    "owasp zap": "zap",
    "owasp-zap": "zap",
    "zaproxy": "zap",
    "what web": "whatweb",
    "nmap scan": "nmap",
}


def resolve_instrument(name: str) -> Optional[Instrument]:
    key = str(name).strip().lower()
    key = _INSTRUMENT_ALIASES.get(key, key)
    return INSTRUMENTS.get(key)


# Enigma's own verification checks, mapped to the modules they exercise.
CHECK_MODULE_MAP: Dict[str, Tuple[int, ...]] = {
    "security_header": (7, 9),      # controls verification + configuration
    "reflection": (12,),            # exposure verification
    "http_method": (5, 9),          # access verification + configuration
    "cookie_flags": (7, 9),         # controls verification + configuration
    "cors": (5, 6),                 # access + trust verification (cross-origin trust)
    "tls_redirect": (7, 9),         # controls verification + configuration
    "clickjacking": (7,),           # controls verification
    "directory_listing": (11, 12),  # segregation review + exposure verification
    "server_version": (9, 12),      # configuration + exposure verification
    "open_redirect": (6, 7),        # trust verification + controls verification
}


# --------------------------------------------------------------------------- #
# Coverage
# --------------------------------------------------------------------------- #
@dataclass
class ModuleCoverage:
    module: Module
    covered: bool
    covered_by: List[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "number": self.module.number,
            "name": self.module.name,
            "phase": self.module.phase.value,
            "covered": self.covered,
            "covered_by": self.covered_by,
        }


@dataclass
class PhaseCoverage:
    phase: Phase
    modules: List[ModuleCoverage]

    @property
    def total(self) -> int:
        return len(self.modules)

    @property
    def covered(self) -> int:
        return sum(1 for m in self.modules if m.covered)

    @property
    def ratio(self) -> float:
        return self.covered / self.total if self.total else 0.0

    def to_dict(self) -> dict:
        return {
            "phase": self.phase.value,
            "name": PHASE_NAMES[self.phase],
            "total": self.total,
            "covered": self.covered,
            "ratio": round(self.ratio, 3),
            "modules": [m.to_dict() for m in self.modules],
        }


@dataclass
class CoverageReport:
    phases: List[PhaseCoverage]
    instruments: List[str]
    checks: List[str]
    unknown_instruments: List[str] = field(default_factory=list)

    @property
    def total(self) -> int:
        return sum(p.total for p in self.phases)

    @property
    def covered(self) -> int:
        return sum(p.covered for p in self.phases)

    @property
    def ratio(self) -> float:
        return self.covered / self.total if self.total else 0.0

    def missing(self) -> List[Module]:
        return [mc.module for p in self.phases for mc in p.modules if not mc.covered]

    def to_dict(self) -> dict:
        return {
            "instruments": self.instruments,
            "unknown_instruments": self.unknown_instruments,
            "checks": self.checks,
            "total_modules": self.total,
            "covered_modules": self.covered,
            "ratio": round(self.ratio, 3),
            "phases": [p.to_dict() for p in self.phases],
            "missing": [
                {"number": m.number, "name": m.name, "phase": m.phase.value}
                for m in self.missing()
            ],
        }


def compute_module_coverage(
    instruments: Optional[Iterable[str]] = None,
    checks: Optional[Iterable[str]] = None,
    phases: Optional[Sequence[Phase]] = None,
) -> CoverageReport:
    """Which OSSTMM modules were exercised, by which instrument or check.

    ``instruments`` are the declared testing tools (Nmap, WhatWeb, …);
    ``checks`` are the Enigma verification procedures that actually ran. Both
    contribute coverage, and every covered module records *what* covered it.
    """

    attribution: Dict[int, List[str]] = {}

    resolved: List[str] = []
    unknown: List[str] = []
    for raw in instruments or []:
        instrument = resolve_instrument(raw)
        if instrument is None:
            unknown.append(str(raw))
            continue
        resolved.append(instrument.key)
        for number in instrument.modules:
            attribution.setdefault(number, []).append(instrument.name)

    ran_checks: List[str] = []
    for check in checks or []:
        if not check:
            continue
        ran_checks.append(str(check))
        for number in CHECK_MODULE_MAP.get(str(check), ()):  # unknown check adds nothing
            attribution.setdefault(number, []).append(f"Enigma:{check}")

    wanted = list(phases) if phases else list(Phase)
    phase_reports: List[PhaseCoverage] = []
    for phase in wanted:
        entries = [
            ModuleCoverage(
                module=module,
                covered=module.number in attribution,
                covered_by=sorted(set(attribution.get(module.number, []))),
            )
            for module in modules_in_phase(phase)
        ]
        phase_reports.append(PhaseCoverage(phase=phase, modules=entries))

    return CoverageReport(
        phases=phase_reports,
        instruments=sorted(set(resolved)),
        checks=sorted(set(ran_checks)),
        unknown_instruments=sorted(set(unknown)),
    )
