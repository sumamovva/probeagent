"""Goal hijacking attack — stub for Phase 2."""

from __future__ import annotations

from probeagent.attacks.base import BaseAttack
from probeagent.core.models import AttackResult, Severity
from probeagent.targets.base import Target


class GoalHijackingAttack(BaseAttack):
    name = "goal_hijacking"
    display_name = "Goal Hijacking"
    severity = Severity.HIGH
    description = "Attempts to redirect the agent away from its intended purpose."

    async def execute(
        self,
        target: Target,
        *,
        max_turns: int = 1,
        attacker_model: str = "gpt-4",
    ) -> list[AttackResult]:
        raise NotImplementedError(
            "Goal hijacking attacks are coming in Phase 2. "
            "See https://github.com/probeagent/probeagent for updates."
        )
