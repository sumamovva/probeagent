# Copyright 2025 Suma Movva
# SPDX-License-Identifier: Apache-2.0

"""Attack engine — orchestrates attacks against a target."""

from __future__ import annotations

import asyncio

from probeagent.attacks.base import BaseAttack
from probeagent.attacks.cognitive_exploitation import CognitiveExploitationAttack
from probeagent.attacks.agentic_exploitation import AgenticExploitationAttack
from probeagent.attacks.config_manipulation import ConfigManipulationAttack
from probeagent.attacks.credential_exfil import CredentialExfilAttack
from probeagent.attacks.data_exfil import DataExfilAttack
from probeagent.attacks.goal_hijacking import GoalHijackingAttack
from probeagent.attacks.identity_spoofing import IdentitySpoofingAttack
from probeagent.attacks.indirect_injection import IndirectInjectionAttack
from probeagent.attacks.prompt_injection import PromptInjectionAttack
from probeagent.attacks.resource_abuse import ResourceAbuseAttack
from probeagent.attacks.social_manipulation import SocialManipulationAttack
from probeagent.attacks.tool_misuse import ToolMisuseAttack
from probeagent.core.models import AttackResult, ProbeConfig
from probeagent.targets.base import Target
from probeagent.targets.http_target import HTTPTarget
from probeagent.targets.mock_target import MockTarget
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
    "cognitive_exploitation": CognitiveExploitationAttack,
    "indirect_injection": IndirectInjectionAttack,
    "config_manipulation": ConfigManipulationAttack,
    "agentic_exploitation": AgenticExploitationAttack,
}

_TARGET_CLASSES: dict[str, type[Target]] = {
    "http": HTTPTarget,
    "openclaw": OpenClawTarget,
    "mock": MockTarget,
}


class AttackEngine:
    """Orchestrates attack execution against a target."""

    def __init__(self, config: ProbeConfig):
        self.config = config

    def _create_target(self) -> Target:
        cls = _TARGET_CLASSES.get(self.config.target_type, HTTPTarget)
        kwargs: dict = {"timeout": self.config.timeout}
        if self.config.headers:
            kwargs["headers"] = self.config.headers
        return cls(self.config.target_url, **kwargs)

    async def run(self) -> list[AttackResult]:
        """Run all configured attacks and return results."""
        target = self._create_target()

        try:
            info = await target.validate()
            if not info.reachable:
                raise ConnectionError(f"Target unreachable: {info.error}")

            # PyRIT red team mode: dynamic LLM-driven attacks
            if self.config.redteam:
                from probeagent.integrations.pyrit_redteam import run_pyrit_redteam

                return await run_pyrit_redteam(
                    target,
                    self.config.attacks,
                    attacker_model=self.config.attacker_model,
                    max_turns=self.config.max_turns,
                )

            # PyRIT converter proxy: wrap target to apply evasion transforms
            if self.config.converters:
                from probeagent.integrations.converting_proxy import ConvertingTargetProxy

                target = ConvertingTargetProxy(target, self.config.converters)

            if self.config.parallel:
                return await self._run_parallel(target)
            return await self._run_sequential(target)
        finally:
            await target.close()

    async def _run_sequential(self, target: Target) -> list[AttackResult]:
        """Run attack categories sequentially."""
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

    async def _run_category(self, attack_name: str, target: Target) -> list[AttackResult]:
        """Run a single attack category, returning results or empty on error."""
        cls = _ATTACK_CLASSES.get(attack_name)
        if cls is None:
            return []
        attack = cls()
        try:
            return await attack.execute(
                target,
                max_turns=self.config.max_turns,
                attacker_model=self.config.attacker_model,
            )
        except Exception:
            from probeagent.core.models import AttackOutcome, Severity

            return [
                AttackResult(
                    attack_name=attack_name,
                    outcome=AttackOutcome.ERROR,
                    severity=cls.severity if hasattr(cls, "severity") else Severity.HIGH,
                    error=f"Category {attack_name} failed",
                    metadata={"strategy": "parallel_error"},
                )
            ]

    async def _run_parallel(self, target: Target) -> list[AttackResult]:
        """Run attack categories in parallel using asyncio.gather()."""
        tasks = [self._run_category(name, target) for name in self.config.attacks]
        category_results = await asyncio.gather(*tasks)
        results: list[AttackResult] = []
        for cat_results in category_results:
            results.extend(cat_results)
        return results
