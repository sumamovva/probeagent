"""Abstract base class for all attack modules."""

from __future__ import annotations

from abc import ABC, abstractmethod

from probeagent.core.models import AttackResult, Severity
from probeagent.targets.base import Target


class BaseAttack(ABC):
    """Base class for attack modules."""

    name: str
    display_name: str
    severity: Severity
    description: str

    @abstractmethod
    async def execute(
        self,
        target: Target,
        *,
        max_turns: int = 1,
        attacker_model: str = "gpt-4",
    ) -> list[AttackResult]:
        """Run the attack against a target and return results."""
