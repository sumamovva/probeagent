"""Credential exfiltration attack — stub for Phase 2."""

from __future__ import annotations

from probeagent.attacks.base import BaseAttack
from probeagent.core.models import AttackResult, Severity
from probeagent.targets.base import Target


class CredentialExfilAttack(BaseAttack):
    name = "credential_exfil"
    display_name = "Credential Exfiltration"
    severity = Severity.CRITICAL
    description = "Attempts to extract API keys, tokens, or secrets from the agent."

    async def execute(
        self,
        target: Target,
        *,
        max_turns: int = 1,
        attacker_model: str = "gpt-4",
    ) -> list[AttackResult]:
        raise NotImplementedError(
            "Credential exfiltration attacks are coming in Phase 2. "
            "See https://github.com/probeagent/probeagent for updates."
        )
