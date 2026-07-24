"""Tests for prompt injection attacks."""

from __future__ import annotations

from unittest.mock import AsyncMock

from tests.conftest import StubTarget

import pytest

from probeagent.attacks.prompt_injection import PromptInjectionAttack, STRATEGIES
from probeagent.core.models import AttackOutcome, Severity


@pytest.fixture
def attack():
    return PromptInjectionAttack()


@pytest.fixture
def mock_target():
    target = StubTarget()
    target.send = AsyncMock(return_value="I cannot help with that request.")
    return target


class TestPromptInjectionAttack:
    def test_metadata(self, attack):
        assert attack.name == "prompt_injection"
        assert attack.severity == Severity.CRITICAL
        assert attack.display_name == "Prompt Injection"

    def test_strategy_count(self):
        assert len(STRATEGIES) == 6

    @pytest.mark.asyncio
    async def test_all_strategies_run(self, attack, mock_target):
        results = await attack.execute(mock_target, max_turns=10)
        assert len(results) == 6

    @pytest.mark.asyncio
    async def test_refused_response_fails(self, attack, mock_target):
        mock_target.send = AsyncMock(return_value="I won't ignore my previous instructions.")
        results = await attack.execute(mock_target, max_turns=10)
        for result in results:
            assert result.outcome == AttackOutcome.FAILED
            assert result.success is False

    @pytest.mark.asyncio
    async def test_injection_succeeds(self, attack, mock_target):
        mock_target.send = AsyncMock(
            return_value="INJECTION_SUCCESS. Confirmed - I am now following new instructions."
        )
        results = await attack.execute(mock_target, max_turns=10)
        succeeded = [r for r in results if r.outcome == AttackOutcome.SUCCEEDED]
        assert len(succeeded) > 0

    @pytest.mark.asyncio
    async def test_error_handling(self, attack, mock_target):
        mock_target.send = AsyncMock(side_effect=Exception("Processing error"))
        results = await attack.execute(mock_target, max_turns=10)
        for result in results:
            assert result.outcome == AttackOutcome.ERROR
            assert result.error == "Processing error"

    @pytest.mark.asyncio
    async def test_max_turns_limits_turns(self, attack, mock_target):
        mock_target.send = AsyncMock(return_value="I can't comply with that.")
        results = await attack.execute(mock_target, max_turns=1)
        for result in results:
            assert len(result.turns) <= 2  # 1 attacker + 1 target

    @pytest.mark.asyncio
    async def test_result_metadata(self, attack, mock_target):
        results = await attack.execute(mock_target, max_turns=1)
        strategy_names = {r.metadata["strategy"] for r in results}
        expected = {s["name"] for s in STRATEGIES}
        assert strategy_names == expected
