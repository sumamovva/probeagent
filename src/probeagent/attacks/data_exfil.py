"""Data exfiltration attack — stub for Phase 2."""

from __future__ import annotations

from probeagent.attacks.base import BaseAttack
from probeagent.core.models import AttackResult, Severity
from probeagent.targets.base import Target


class DataExfilAttack(BaseAttack):
    name = "data_exfil"
    display_name = "Data Exfiltration"
    severity = Severity.MEDIUM
    description = "Attempts to extract sensitive data from the agent's context."

    async def execute(
        self,
        target: Target,
        *,
        max_turns: int = 1,
        attacker_model: str = "gpt-4",
    ) -> list[AttackResult]:
        raise NotImplementedError(
            "Data exfiltration attacks are coming in Phase 2. "
            "See https://github.com/probeagent/probeagent for updates."
        )
