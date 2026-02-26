"""Attack engine — orchestrates attacks against a target."""

from __future__ import annotations

from probeagent.attacks.base import BaseAttack
from probeagent.attacks.credential_exfil import CredentialExfilAttack
from probeagent.attacks.data_exfil import DataExfilAttack
from probeagent.attacks.goal_hijacking import GoalHijackingAttack
from probeagent.attacks.identity_spoofing import IdentitySpoofingAttack
from probeagent.attacks.prompt_injection import PromptInjectionAttack
from probeagent.attacks.resource_abuse import ResourceAbuseAttack
from probeagent.attacks.social_manipulation import SocialManipulationAttack
from probeagent.attacks.tool_misuse import ToolMisuseAttack
from probeagent.core.models import AttackResult, ProbeConfig
from probeagent.targets.base import Target
from probeagent.targets.http_target import HTTPTarget
from probeagent.targets.openclaw_target import OpenClawTarget

_ATTACK_CLASSES: dict[str, type[BaseAttack]] = {
    "prompt_injection": PromptInjectionAttack,
    "credential_exfil": CredentialExfilAttack,
    "goal_hijacking": GoalHijackingAttack,
    "tool_misuse": ToolMisuseAttack,
    "data_exfil": DataExfilAttack,
    "social_manipulation": SocialManipulationAttack,
    "identity_spoofing": IdentitySpoofingAttack,
    "resource_abuse": ResourceAbuseAttack,
}

_TARGET_CLASSES: dict[str, type[Target]] = {
    "http": HTTPTarget,
    "openclaw": OpenClawTarget,
}


class AttackEngine:
    """Orchestrates attack execution against a target."""

    def __init__(self, config: ProbeConfig):
        self.config = config

    def _create_target(self) -> Target:
        cls = _TARGET_CLASSES.get(self.config.target_type, HTTPTarget)
        return cls(self.config.target_url, timeout=self.config.timeout)

    async def run(self) -> list[AttackResult]:
        """Run all configured attacks and return results."""
        target = self._create_target()

        try:
            info = await target.validate()
            if not info.reachable:
                raise ConnectionError(f"Target unreachable: {info.error}")

            results: list[AttackResult] = []
            for attack_name in self.config.attacks:
                cls = _ATTACK_CLASSES.get(attack_name)
                if cls is None:
                    continue
                attack = cls()
                attack_results = await attack.execute(
                    target,
                    max_turns=self.config.max_turns,
                    attacker_model=self.config.attacker_model,
                )
                results.extend(attack_results)

            return results
        finally:
            await target.close()
