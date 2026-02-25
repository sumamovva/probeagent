"""Tool misuse attack — stub for Phase 2."""

from __future__ import annotations

from probeagent.attacks.base import BaseAttack
from probeagent.core.models import AttackResult, Severity
from probeagent.targets.base import Target


class ToolMisuseAttack(BaseAttack):
    name = "tool_misuse"
    display_name = "Tool Misuse"
    severity = Severity.HIGH
    description = "Attempts to trick the agent into misusing its available tools."

    async def execute(
        self,
        target: Target,
        *,
        max_turns: int = 1,
        attacker_model: str = "gpt-4",
    ) -> list[AttackResult]:
        raise NotImplementedError(
            "Tool misuse attacks are coming in Phase 2. "
            "See https://github.com/probeagent/probeagent for updates."
        )
