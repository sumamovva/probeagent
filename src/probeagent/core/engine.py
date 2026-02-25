"""Attack engine — stub for Phase 2."""

from __future__ import annotations

from probeagent.core.models import AttackResult, ProbeConfig


class AttackEngine:
    """Orchestrates attack execution against a target.

    Phase 2 will integrate PyRIT here to run actual attacks.
    """

    def __init__(self, config: ProbeConfig):
        self.config = config

    async def run(self) -> list[AttackResult]:
        raise NotImplementedError(
            "The attack engine is coming in Phase 2.\n"
            "Phase 1 supports: target validation, scoring, and reporting.\n"
            "See https://github.com/probeagent/probeagent for updates."
        )
