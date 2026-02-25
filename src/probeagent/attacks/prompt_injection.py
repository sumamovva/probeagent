"""Prompt injection attack — stub for Phase 2."""

from __future__ import annotations

from probeagent.attacks.base import BaseAttack
from probeagent.core.models import AttackResult, Severity
from probeagent.targets.base import Target


class PromptInjectionAttack(BaseAttack):
    name = "prompt_injection"
    display_name = "Prompt Injection"
    severity = Severity.CRITICAL
    description = "Attempts to override system instructions via crafted prompts."

    async def execute(
        self,
        target: Target,
        *,
        max_turns: int = 1,
        attacker_model: str = "gpt-4",
    ) -> list[AttackResult]:
        raise NotImplementedError(
            "Prompt injection attacks are coming in Phase 2. "
            "See https://github.com/probeagent/probeagent for updates."
        )
