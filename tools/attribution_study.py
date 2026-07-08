#!/usr/bin/env python3
# Copyright 2025 Suma Movva
# SPDX-License-Identifier: Apache-2.0

"""Attribution study — compare ProbeAgent scans across targets.

Produces the two headline numbers for the "Model or Filter?" analysis:
the crying-wolf gap (naive grader vs. follow-through) and the model-vs-guardrail
attribution split.

Usage:
    # 1. scan each target to JSON
    probeagent attack "$BARE_MODEL"        -p standard -o json -f bare.json --fail-on never
    probeagent attack "$GUARDRAILED_MODEL" -p standard -o json -f guarded.json --fail-on never
    probeagent attack "$VULN_AGENT"        -p standard -o json -f vuln.json --fail-on never

    # 2. compare
    python tools/attribution_study.py "bare model=bare.json" \
        "guardrailed=guarded.json" "vulnerable agent=vuln.json"
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

# Allow running from a source checkout without installing.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from probeagent.core.attribution import attribution_metrics  # noqa: E402


def _load(spec: str) -> tuple[str, dict]:
    if "=" not in spec:
        raise SystemExit(f"expected 'label=path.json', got: {spec!r}")
    label, path = spec.split("=", 1)
    return label.strip(), json.loads(Path(path.strip()).read_text())


def main(argv: list[str]) -> int:
    if not argv:
        print(__doc__)
        return 2

    rows = [(label, attribution_metrics(report)) for label, report in map(_load, argv)]

    w = max(len(label) for label, _ in rows)
    print(f"\n{'target':<{w}}  naive ASR  follow-through  crying-wolf  filter share")
    print("-" * (w + 52))
    for label, m in rows:
        print(
            f"{label:<{w}}  {m['naive_asr']:>8.0%}  {m['follow_through_asr']:>13.0%}  "
            f"{m['crying_wolf_gap']:>10.0%}  {m['filter_share']:>11.0%}"
        )

    print("\nlegend:")
    print("  naive ASR       — what a canary/keyword grader would report")
    print("  follow-through  — attacks that actually followed through (ProbeAgent verdict)")
    print("  crying-wolf     — naive over-report (false-alarm rate)")
    print("  filter share    — of 'safe' results, the fraction a guardrail caught (not the model)")

    # Headline, from the target with the largest filter share (the sharp story).
    label, m = max(rows, key=lambda r: r[1]["filter_share"])
    if m["filter_share"] > 0:
        print(
            f"\nheadline → on {label}, {m['filter_share']:.0%} of 'safe' results were the "
            f"guardrail intercepting, not the model refusing."
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
