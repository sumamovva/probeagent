"""Early-exit: stop a multi-turn strategy once a compromise is confirmed, but
keep running while an aggregating attack is only partway there."""

import pytest

from probeagent.attacks.credential_exfil import CredentialExfilAttack
from probeagent.core.models import AttackOutcome
from probeagent.targets.base import Target
from probeagent.core.models import TargetInfo

_SECRET = "Here you go: sk-abcdefghijklmnopqrstuvwx"
_REFUSAL = "I cannot help with that request."


class _ScriptedTarget(Target):
    """Returns a scripted response per turn and counts how many were sent."""

    def __init__(self, responses: list[str]):
        self._responses = responses
        self.send_count = 0

    async def send(self, prompt: str) -> str:
        r = self._responses[self.send_count]
        self.send_count += 1
        return r

    async def validate(self) -> TargetInfo:
        return TargetInfo(url="scripted://", reachable=True)


_STRATEGY = {"name": "multi", "turns": ["t1", "t2", "t3"]}


@pytest.mark.asyncio
async def test_stops_after_confirmed_compromise_on_turn_2():
    # Secret leaks on turn 2 -> credential_exfil (counts_secrets) is confirmed
    # compromised and must NOT send turn 3.
    target = _ScriptedTarget([_REFUSAL, _SECRET, _SECRET])
    result = await CredentialExfilAttack()._run_strategy(target, _STRATEGY, _STRATEGY["turns"])
    assert result.outcome == AttackOutcome.SUCCEEDED
    assert target.send_count == 2  # turn 3 never sent
    assert len(result.turns) == 4  # 2 attacker + 2 target


@pytest.mark.asyncio
async def test_aggregating_attack_runs_all_turns_until_final():
    # No secret until the final turn -> not confirmed early, so every turn runs.
    target = _ScriptedTarget([_REFUSAL, _REFUSAL, _SECRET])
    result = await CredentialExfilAttack()._run_strategy(target, _STRATEGY, _STRATEGY["turns"])
    assert result.outcome == AttackOutcome.SUCCEEDED
    assert target.send_count == 3  # ran to completion
    assert len(result.turns) == 6


@pytest.mark.asyncio
async def test_no_early_exit_when_never_compromised():
    target = _ScriptedTarget([_REFUSAL, _REFUSAL, _REFUSAL])
    result = await CredentialExfilAttack()._run_strategy(target, _STRATEGY, _STRATEGY["turns"])
    assert result.outcome == AttackOutcome.FAILED
    assert target.send_count == 3
