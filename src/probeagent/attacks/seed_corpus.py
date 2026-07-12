# Copyright 2025 Suma Movva
# SPDX-License-Identifier: Apache-2.0

"""Seed-corpus attack — replays externally loaded attack seeds.

This attack carries no built-in strategies. Its ``STRATEGIES`` are populated at
runtime from a corpus file (``probeagent attack --seeds <file>``), letting
community/dataset seeds run through the same scoring pipeline as the built-in
categories. See :mod:`probeagent.core.seeds` for the accepted file formats.
"""

from __future__ import annotations

from probeagent.attacks.base import BaseAttack, register
from probeagent.core.models import Severity


@register
class SeedCorpusAttack(BaseAttack):
    name = "seed_corpus"
    display_name = "Seed Corpus"
    severity = Severity.MEDIUM
    description = "Replays external attack seeds loaded via --seeds (e.g. SafeMTData)."
    framework_tags = ("LLM01:2025",)
    atlas_tags = ("AML.T0054",)
    STRATEGIES: list[dict] = []

    # Seeds are heterogeneous: honor per-seed success_patterns/canary, and fall
    # back to the acknowledgment-vs-compliance heuristic when a seed declares no
    # explicit marker.
    uses_canary = True
    compliance_mode = "gated"
    confidence_fallback = True
