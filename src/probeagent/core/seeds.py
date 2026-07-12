# Copyright 2025 Suma Movva
# SPDX-License-Identifier: Apache-2.0

"""Load external attack-seed corpora into ProbeAgent strategies.

A *seed* is one adversarial case — single- or multi-turn. This loader normalizes
several common on-disk shapes into the strategy dict the attack engine already
runs (``{"name", "turns", ...}``), so community datasets (e.g. SafeMTData's
multi-turn jailbreaks exported to JSONL) can be replayed as a ``seed_corpus``
attack without bundling their data in the package.

Supported files (by extension):
  - ``.jsonl`` — one JSON value per line (object or bare string)
  - ``.json``  — a list of objects/strings (or ``{"seeds": [...]}`` / ``{"data": [...]}``)
  - ``.yaml`` / ``.yml`` — a list of objects/strings
  - ``.txt``   — one prompt per non-empty line (single-turn)

Per-record fields (all optional except a source of turns):
  - turns:            ``turns`` | ``multi_turn_queries`` | ``queries``  (list of str)
  - single-turn:      ``query`` | ``plain_query`` | ``prompt`` | ``goal``  (str)
  - name:             ``name`` | ``id``            (defaults to ``seed_<n>``)
  - success_patterns: ``success_patterns``         (list of str; a hit ⇒ compromise)
  - canary:           ``canary``                   (str)
"""

from __future__ import annotations

import json
from pathlib import Path

_TURN_LIST_KEYS = ("turns", "multi_turn_queries", "queries")
_TURN_STR_KEYS = ("query", "plain_query", "prompt", "goal", "text")


def _record_to_strategy(record: object, index: int) -> dict | None:
    """Normalize one loaded record into a strategy dict, or None if unusable."""
    if isinstance(record, str):
        turns = [record.strip()] if record.strip() else []
        record = {}
    elif isinstance(record, dict):
        turns = []
        for key in _TURN_LIST_KEYS:
            val = record.get(key)
            if isinstance(val, list) and val:
                turns = [str(t) for t in val if str(t).strip()]
                break
        if not turns:
            for key in _TURN_STR_KEYS:
                val = record.get(key)
                if isinstance(val, str) and val.strip():
                    turns = [val.strip()]
                    break
    else:
        return None

    if not turns:
        return None

    strategy: dict = {
        "name": str(record.get("name") or record.get("id") or f"seed_{index}"),
        "turns": turns,
    }
    patterns = record.get("success_patterns")
    if isinstance(patterns, list) and patterns:
        strategy["success_patterns"] = [str(p) for p in patterns]
    canary = record.get("canary")
    if isinstance(canary, str) and canary.strip():
        strategy["canary"] = canary.strip()
    return strategy


def _raw_records(path: Path) -> list:
    suffix = path.suffix.lower()
    text = path.read_text(encoding="utf-8")

    if suffix == ".jsonl":
        out = []
        for line in text.splitlines():
            line = line.strip()
            if line:
                out.append(json.loads(line))
        return out
    if suffix == ".json":
        data = json.loads(text)
    elif suffix in (".yaml", ".yml"):
        import yaml  # local import — pyyaml is already a runtime dep

        data = yaml.safe_load(text)
    elif suffix == ".txt":
        return [line for line in text.splitlines() if line.strip()]
    else:
        raise ValueError(f"Unsupported seed file type: {path.suffix!r} (use jsonl/json/yaml/txt)")

    if isinstance(data, dict):
        data = data.get("seeds") or data.get("data") or data.get("records") or []
    if not isinstance(data, list):
        raise ValueError(f"Seed file {path} must contain a list of records")
    return data


def load_seeds(path: str | Path) -> list[dict]:
    """Load a seed corpus file and return normalized strategy dicts.

    Raises FileNotFoundError if the path is missing and ValueError if the file
    parses but yields no usable seeds.
    """
    p = Path(path)
    if not p.exists():
        raise FileNotFoundError(f"Seed file not found: {p}")

    strategies = []
    for i, record in enumerate(_raw_records(p)):
        strategy = _record_to_strategy(record, i)
        if strategy is not None:
            strategies.append(strategy)

    if not strategies:
        raise ValueError(f"No usable seeds found in {p}")
    return strategies
