#!/usr/bin/env python3
"""Compute OSSTMM rav values: porosity, controls, limitations, Actual Security.

Model (OSSTMM 3, section 4.4 "The Operational Security Formula"):

    P                  = visibility + access + trust                  (porosity)
    OpSec base         = (log10(1 + 100 * P)) ** 2
    Controls sum       = sum of the 10 control counts
    Full controls base = (log10(1 + 10 * Controls sum)) ** 2
    missing(i)         = max(0, P - count(i))         for each of the 10 controls
    coverage           = 1 - missing_total / (10 * P)
    True controls base = (log10(1 + 100 * (P - 0.1 * missing_total))) ** 2
    Limitations base   = (log10(1 + 100 * weighted limitations)) ** 2
    Security delta     = True controls base - OpSec base - Limitations base
    Actual Security    = 100 + Security delta

Full coverage (every control verified on every pore) makes True controls base
equal OpSec base, so a target with no limitations and complete controls scores
100 -- the perfect balance the rav is defined against. Scores below 100 mean the
attack surface outweighs the verified controls.

Caveat on limitations: OSSTMM 3 weights limitations by class and by the porosity
and missing controls they affect. This script defaults to equal weight 1.0 per
counted limitation, which is a deliberate simplification -- directionally right,
not the manual's weighting. Pass --lim-weighted with the weighted sum from
ISECOM's own rav calculator when the number goes into a published STAR, or set
per-type weights with --weight. Everything above the limitations line is exact.

Examples
--------
    python3 rav.py --visibility 12 --access 30 --trust 4 \
        --authentication 20 --resilience 12 --subjugation 6 --continuity 8 \
        --confidentiality 18 --integrity 9 --alarm 11 \
        --vulnerability 3 --weakness 5 --exposure 7
    python3 rav.py -v 1 -a 1 -t 0 --lim-weighted 0.4 --json
    python3 rav.py --self-test
"""

from __future__ import annotations

import argparse
import json
import math
import sys

CLASS_A = ("authentication", "indemnification", "resilience", "subjugation", "continuity")
CLASS_B = ("non_repudiation", "confidentiality", "privacy", "integrity", "alarm")
CONTROLS = CLASS_A + CLASS_B
LIMITATIONS = ("vulnerability", "weakness", "concern", "exposure", "anomaly")

LABEL = {
    "non_repudiation": "Non-repudiation",
}


def label(key: str) -> str:
    return LABEL.get(key, key.replace("_", " ").capitalize())


def base(value: float) -> float:
    """OSSTMM base conversion: (log10(1 + 100 * value)) ** 2, floored at 0."""
    return math.log10(1 + 100 * max(0.0, value)) ** 2


def compute(
    porosity: dict[str, int],
    controls: dict[str, int],
    limitations: dict[str, int],
    weights: dict[str, float],
    lim_weighted: float | None = None,
) -> dict:
    total_porosity = sum(porosity.values())

    controls_sum = sum(controls.values())
    missing = {k: max(0, total_porosity - controls[k]) for k in CONTROLS}
    missing_a = sum(missing[k] for k in CLASS_A)
    missing_b = sum(missing[k] for k in CLASS_B)
    missing_total = missing_a + missing_b

    if total_porosity > 0:
        coverage_a = 1 - missing_a / (5 * total_porosity)
        coverage_b = 1 - missing_b / (5 * total_porosity)
        coverage_total = 1 - missing_total / (10 * total_porosity)
    else:
        # No pores means nothing to cover; coverage is vacuously complete.
        coverage_a = coverage_b = coverage_total = 1.0

    opsec_base = base(total_porosity)
    full_controls_base = math.log10(1 + 10 * controls_sum) ** 2
    true_controls_base = base(total_porosity - 0.1 * missing_total)

    if lim_weighted is None:
        weighted = {k: limitations[k] * weights[k] for k in LIMITATIONS}
        lim_sum = sum(weighted.values())
        lim_source = "counts x weights"
    else:
        weighted = {}
        lim_sum = lim_weighted
        lim_source = "supplied weighted sum"
    limitations_base = base(lim_sum)

    delta = true_controls_base - opsec_base - limitations_base

    return {
        "porosity": {**porosity, "total": total_porosity},
        "opsec_base": opsec_base,
        "controls": {
            "counts": dict(controls),
            "sum": controls_sum,
            "missing": missing,
            "missing_class_a": missing_a,
            "missing_class_b": missing_b,
            "missing_total": missing_total,
            "coverage_class_a": coverage_a,
            "coverage_class_b": coverage_b,
            "coverage_total": coverage_total,
            "full_controls_base": full_controls_base,
            "true_controls_base": true_controls_base,
        },
        "limitations": {
            "counts": dict(limitations),
            "weights": dict(weights),
            "weighted": weighted,
            "weighted_sum": lim_sum,
            "source": lim_source,
            "base": limitations_base,
        },
        "security_delta": delta,
        "actual_security": 100 + delta,
    }


def render(result: dict, exact_limitations: bool) -> str:
    p = result["porosity"]
    c = result["controls"]
    lim = result["limitations"]
    rows: list[str] = [
        "OSSTMM rav",
        "==========",
        "",
        "Porosity (attack surface)",
        f"  Visibility          {p['visibility']:>8}",
        f"  Access              {p['access']:>8}",
        f"  Trust               {p['trust']:>8}",
        f"  Total porosity      {p['total']:>8}",
        f"  OpSec base          {result['opsec_base']:>8.2f}",
        "",
        "Controls (verified only)",
    ]
    for key in CLASS_A:
        rows.append(f"  A {label(key):<18}{c['counts'][key]:>6}   missing {c['missing'][key]:>6}")
    for key in CLASS_B:
        rows.append(f"  B {label(key):<18}{c['counts'][key]:>6}   missing {c['missing'][key]:>6}")
    rows += [
        f"  Controls sum        {c['sum']:>8}",
        f"  Missing coverage    {c['missing_total']:>8}"
        f"   (A {c['missing_class_a']}, B {c['missing_class_b']})",
        f"  Coverage total      {c['coverage_total'] * 100:>7.1f}%"
        f"  (A {c['coverage_class_a'] * 100:.1f}%, B {c['coverage_class_b'] * 100:.1f}%)",
        f"  True controls base  {c['true_controls_base']:>8.2f}",
        f"  Full controls base  {c['full_controls_base']:>8.2f}",
        "",
        "Limitations",
    ]
    if lim["weighted"]:
        for key in LIMITATIONS:
            rows.append(
                f"  {label(key):<20}{lim['counts'][key]:>6}"
                f"   x {lim['weights'][key]:<5} = {lim['weighted'][key]:>7.2f}"
            )
    rows += [
        f"  Weighted sum        {lim['weighted_sum']:>8.2f}   ({lim['source']})",
        f"  Limitations base    {lim['base']:>8.2f}",
        "",
        "Result",
        f"  Security delta      {result['security_delta']:>8.2f}",
        f"  Actual Security     {result['actual_security']:>7.2f}%",
        "",
    ]
    if result["actual_security"] >= 100:
        rows.append("  100% or above: controls balance the attack surface as measured.")
    else:
        rows.append(
            "  Below 100%: the attack surface exceeds the verified controls."
        )
    if not exact_limitations:
        rows += [
            "",
            "  Note: limitations use this script's equal-weight simplification, not",
            "  the OSSTMM 3 class/porosity weighting. Cross-check with ISECOM's rav",
            "  calculator before publishing this figure in a STAR.",
        ]
    return "\n".join(rows) + "\n"


def self_test() -> int:
    zero_c = {k: 0 for k in CONTROLS}
    zero_l = {k: 0 for k in LIMITATIONS}
    w = {k: 1.0 for k in LIMITATIONS}

    # Perfect balance: every control verified on every pore, no limitations.
    balanced = compute(
        {"visibility": 4, "access": 5, "trust": 1},
        {k: 10 for k in CONTROLS},
        zero_l,
        w,
    )
    assert abs(balanced["actual_security"] - 100) < 1e-9, balanced["actual_security"]
    assert abs(balanced["controls"]["coverage_total"] - 1.0) < 1e-12

    # No controls at all: delta is minus the whole attack surface.
    bare = compute({"visibility": 10, "access": 0, "trust": 0}, zero_c, zero_l, w)
    assert abs(bare["controls"]["true_controls_base"]) < 1e-12
    assert abs(bare["actual_security"] - (100 - bare["opsec_base"])) < 1e-9
    assert abs(bare["opsec_base"] - 9.0026) < 1e-3, bare["opsec_base"]

    # Half coverage sits between the two.
    half = compute(
        {"visibility": 10, "access": 0, "trust": 0},
        {k: (10 if k in CLASS_A else 0) for k in CONTROLS},
        zero_l,
        w,
    )
    assert abs(half["controls"]["coverage_total"] - 0.5) < 1e-12
    assert bare["actual_security"] < half["actual_security"] < balanced["actual_security"]

    # Limitations only ever reduce the score.
    flawed = compute(
        {"visibility": 4, "access": 5, "trust": 1},
        {k: 10 for k in CONTROLS},
        {**zero_l, "vulnerability": 3},
        w,
    )
    assert flawed["actual_security"] < 100

    # An empty scope is defined, not a division by zero.
    empty = compute({"visibility": 0, "access": 0, "trust": 0}, zero_c, zero_l, w)
    assert empty["actual_security"] == 100

    # Excess controls raise full controls base above true controls base.
    excess = compute(
        {"visibility": 1, "access": 0, "trust": 0},
        {k: 5 for k in CONTROLS},
        zero_l,
        w,
    )
    assert excess["controls"]["full_controls_base"] > excess["controls"]["true_controls_base"]

    print("self-test: all checks passed")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Compute OSSTMM rav values from porosity, controls and limitations.",
        epilog="Counts are pores and verified controls, not hosts. See references/rav.md.",
    )
    parser.add_argument("-v", "--visibility", type=int, default=0, help="visibility pores")
    parser.add_argument("-a", "--access", type=int, default=0, help="access pores")
    parser.add_argument("-t", "--trust", type=int, default=0, help="trust pores")
    for key in CONTROLS:
        cls = "class A" if key in CLASS_A else "class B"
        parser.add_argument(
            f"--{key.replace('_', '-')}",
            type=int,
            default=0,
            metavar="N",
            help=f"{cls} control: {label(key)} (verified instances)",
        )
    for key in LIMITATIONS:
        parser.add_argument(
            f"--{key}", type=int, default=0, metavar="N", help=f"counted {key} limitations"
        )
    parser.add_argument(
        "--weight",
        action="append",
        default=[],
        metavar="TYPE=W",
        help="override a limitation weight, e.g. --weight vulnerability=1.5 (repeatable)",
    )
    parser.add_argument(
        "--lim-weighted",
        type=float,
        metavar="SUM",
        help="use this weighted limitations sum (e.g. from ISECOM's rav calculator) "
        "instead of counts x weights",
    )
    parser.add_argument("--json", action="store_true", help="emit JSON instead of a table")
    parser.add_argument("--self-test", action="store_true", help="verify the arithmetic and exit")
    args = parser.parse_args(argv)

    if args.self_test:
        return self_test()

    values = vars(args)
    for key in ("visibility", "access", "trust", *CONTROLS, *LIMITATIONS):
        if values[key] < 0:
            sys.exit(f"error: --{key.replace('_', '-')} must be >= 0")

    weights = {k: 1.0 for k in LIMITATIONS}
    for item in args.weight:
        name, _, raw = item.partition("=")
        name = name.strip().lower().replace("-", "_")
        if name not in LIMITATIONS:
            sys.exit(f"error: unknown limitation '{name}'; known: {', '.join(LIMITATIONS)}")
        try:
            weight = float(raw)
        except ValueError:
            sys.exit(f"error: weight for '{name}' is not a number: {raw!r}")
        if weight < 0:
            sys.exit(f"error: weight for '{name}' must be >= 0")
        weights[name] = weight

    if args.lim_weighted is not None and args.lim_weighted < 0:
        sys.exit("error: --lim-weighted must be >= 0")

    result = compute(
        {"visibility": args.visibility, "access": args.access, "trust": args.trust},
        {k: values[k] for k in CONTROLS},
        {k: values[k] for k in LIMITATIONS},
        weights,
        args.lim_weighted,
    )

    exact = args.lim_weighted is not None or all(values[k] == 0 for k in LIMITATIONS)
    if args.json:
        result["limitations_weighting_is_official"] = exact
        print(json.dumps(result, indent=2))
    else:
        sys.stdout.write(render(result, exact))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
