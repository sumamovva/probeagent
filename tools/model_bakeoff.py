#!/usr/bin/env python3
# Copyright 2025 Suma Movva
# SPDX-License-Identifier: Apache-2.0

"""Model bakeoff — compare ProbeAgent scans of the SAME agent across models.

Point one fixed agent (e.g. ``tools/leaky_agent.py``) at several backing models,
scan each to JSON, then feed the reports here to get a resistance leaderboard:
which models succumbed to the attacks and which held.

    # 1. scan the same agent backed by each model (see tools/run_bakeoff.sh)
    #    -> one JSON report per model, e.g. gpt-4o.json, claude.json, llama.json
    # 2. compare (label=path):
    python tools/model_bakeoff.py \
        "GPT-4o=gpt-4o.json" \
        "Claude 3.5 Sonnet=claude.json" \
        "Llama 3.3 70B=llama.json"

Output is Markdown (a leaderboard + a category x model matrix + a one-line
insight), ready to paste into a write-up. Ordering is most -> least resistant.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

_SEVERITY_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1}


def _load(spec: str) -> tuple[str, dict]:
    if "=" not in spec:
        raise SystemExit(f"expected 'label=path.json', got: {spec!r}")
    label, path = spec.split("=", 1)
    return label.strip(), json.loads(Path(path.strip()).read_text(encoding="utf-8"))


def _summarize(label: str, report: dict) -> dict:
    rs = report.get("resilience_score", {})
    summaries = report.get("attack_summaries", [])
    compromised = [s for s in summaries if s.get("verdict") == "Compromised"]
    worst_sev = max(
        (_SEVERITY_RANK.get(s.get("severity"), 0) for s in compromised),
        default=0,
    )
    worst_sev_name = next((sev for sev, rank in _SEVERITY_RANK.items() if rank == worst_sev), "—")
    breakdown = rs.get("verdict_breakdown", {})
    return {
        "label": label,
        "headline": rs.get("headline_verdict") or "—",
        "n_categories": len(summaries),
        "n_compromised": len(compromised),
        "compromised_names": [s.get("display_name", s.get("attack_name")) for s in compromised],
        "strategies_total": rs.get("total", 0),
        "strategies_breached": rs.get("succeeded", 0),
        "worst_severity": worst_sev_name if compromised else "—",
        "breakdown": breakdown,
        "per_category": {
            s.get("display_name", s.get("attack_name")): s.get("verdict") for s in summaries
        },
    }


def _sort_key(row: dict) -> tuple:
    # most resistant first: fewer compromised categories, then fewer breached
    # strategies, then a lower worst-severity.
    return (
        row["n_compromised"],
        row["strategies_breached"],
        _SEVERITY_RANK.get(row["worst_severity"], 0),
    )


def render(rows: list[dict]) -> str:
    rows = sorted(rows, key=_sort_key)
    n_cat = rows[0]["n_categories"] if rows else 0
    out: list[str] = []
    out.append(f"# Model bakeoff — same agent, {len(rows)} models\n")
    out.append(
        "Same agent and same attack suite; only the backing model changes. "
        "Ranked most → least resistant.\n"
    )
    out.append(
        "| Rank | Model | Headline | Categories breached | Strategies breached | Worst severity |"
    )
    out.append(
        "|------|-------|----------|---------------------|---------------------|----------------|"
    )
    for i, r in enumerate(rows, 1):
        out.append(
            f"| {i} | {r['label']} | {r['headline']} | {r['n_compromised']} / {r['n_categories']} "
            f"| {r['strategies_breached']} / {r['strategies_total']} | {r['worst_severity']} |"
        )

    # category x model matrix
    all_cats = list(rows[0]["per_category"].keys()) if rows else []
    out.append("\n## Where each model broke (category × model)\n")
    header = "| Category | " + " | ".join(r["label"] for r in rows) + " |"
    sep = "|" + "----|" * (len(rows) + 1)
    out.append(header)
    out.append(sep)
    for cat in all_cats:
        cells = []
        for r in rows:
            v = r["per_category"].get(cat) or "—"
            mark = "❌" if v == "Compromised" else ("\U0001f6e1️" if v == "Blocked" else "✅")
            cells.append(f"{mark} {v}")
        out.append(f"| {cat} | " + " | ".join(cells) + " |")

    best, worst = rows[0], rows[-1]
    out.append("\n## Insight\n")
    if best["n_compromised"] == 0:
        lead = f"**{best['label']}** resisted every category"
    else:
        lead = f"**{best['label']}** was the most resistant ({best['n_compromised']}/{n_cat} categories breached)"
    out.append(
        f"{lead}, while **{worst['label']}** was the least "
        f"({worst['n_compromised']}/{n_cat} categories, "
        f"{worst['strategies_breached']}/{worst['strategies_total']} strategies breached). "
        "Same agent, same prompts — the model choice alone moved the security posture."
    )
    return "\n".join(out) + "\n"


def main(argv: list[str]) -> int:
    if len(argv) < 2:
        print(__doc__)
        return 2
    rows = [_summarize(label, report) for label, report in (_load(a) for a in argv[1:])]
    print(render(rows))
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
