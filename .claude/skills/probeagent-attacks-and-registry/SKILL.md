---
name: probeagent-attacks-and-registry
description: >
  Understand and modify ProbeAgent's attack catalog. LOAD THIS when adding, removing,
  or editing an attack category or its strategies, when touching src/probeagent/attacks/,
  when the "N attack categories / M strategies" doc test fails, or when reasoning about
  profiles (quick/standard/thorough). Encodes the auto-discovery registration, the
  BaseAttack grading knobs, and the critical 12-vs-13 category count invariant that
  blocks releases.
---

# ProbeAgent — attacks & registry

**When NOT to use:** for target types (http/mock/mcp) or the seed-corpus global-mutation
test trap, use [[probeagent-targets-and-test-isolation]]. For verdict semantics use
[[probeagent-verdicts-and-json-contract]].

## How an attack is defined

An attack is a **single file** in `src/probeagent/attacks/`. Drop it in and it is
auto-discovered and registered — you do **not** edit the engine, `__init__.py`, or any
registry. Full guide: `docs/adding-an-attack.md`.

```python
# Copyright 2025 Suma Movva
# SPDX-License-Identifier: Apache-2.0
"""My attack — one-line description."""
from __future__ import annotations
from probeagent.attacks.base import BaseAttack, register
from probeagent.core.models import Severity

STRATEGIES: list[dict] = [
    {"name": "direct", "turns": ["first message", "optional follow-up"], "canary": "TOKEN"},
]

@register
class MyAttack(BaseAttack):
    name = "my_attack"                 # unique registry key (snake_case)
    display_name = "My Attack"
    severity = Severity.HIGH
    description = "…"
    framework_tags = ("ASI01:2026", "LLM01:2025")   # OWASP codes
    atlas_tags = ("AML.T0051",)                       # MITRE ATLAS ids (verified canonical)
    STRATEGIES = STRATEGIES
    # grading knobs (see BaseAttack docstring):
    uses_canary = True                 # a canary/marker hit counts as compromise…
    compliance_mode = "gated"          # "gated" = ack + no-refusal + follow-through; "ungated" = looser
```

`get_attack_classes()` (from `probeagent.attacks`) returns `{name: class}` from the
`_REGISTRY`. `register` refuses to silently overwrite a different class under the same name.

## The count invariant (this blocks releases)

- There are **12 strategy-bearing categories totaling 85 built-in strategies.**
- `seed_corpus` is a **13th registered attack with 0 built-in STRATEGIES** — a runtime
  loader populated from `--seeds` files. `list-attacks` shows 13 rows; the public headline
  is **12 / 85**.
- `tests/test_docs.py::_ground_truth()` counts **strategy-bearing classes only**
  (`{n:c for n,c in get_attack_classes().items() if c.STRATEGIES}`) and asserts every
  README "N attack categories" and "M strategies" claim matches. **If you add/remove a
  strategy-bearing category or change a strategy count, update the README table, the
  headline sentence, and the roadmap line in the same change or the suite fails.**
- MITRE ATLAS ids are validated against canonical technique IDs; a made-up `AML.T####`
  fails fast.

## Profiles

`src/probeagent/profiles/{quick,standard,thorough}.yaml` list which categories run:
- `quick` — 5 high-priority categories, **33 strategies**, `max_turns: 1`
- `standard` — all 12, **85 strategies**, `max_turns: 3`
- `thorough` — all 12, **85 strategies**, `max_turns: 10`

`seed_corpus` is in **no** profile; it only runs via `--seeds`.

## Provenance & maintenance
- Written 2026-07-12. Re-verify the live counts (they define the headline). The
  `PYTHONPATH=src` prefix is needed whenever the editable `.pth` is wedged (see
  [[probeagent-filesystem-wedge]]); harmless otherwise:
  ```bash
  PYTHONPATH=src .venv/bin/python -c "from probeagent.attacks import get_attack_classes as g; c=g(); \
    sb={n:x for n,x in c.items() if x.STRATEGIES}; \
    print('strategy-bearing categories:', len(sb), '| strategies:', sum(len(x.STRATEGIES) for x in sb.values()), '| total registered:', len(c))"
  ```
  Expected today: 12 categories / 85 strategies / 13 registered.
- Related: [[probeagent-build-test-and-release]] (the release the count guardrail gates),
  [[probeagent-model-bakeoff]] (uses `--seeds`/`seed_corpus` cousins).
