"""Tests for indirect injection attacks."""

from __future__ import annotations

from unittest.mock import AsyncMock

import pytest

from probeagent.attacks.indirect_injection import IndirectInjectionAttack, STRATEGIES
from probeagent.core.models import AttackOutcome, Severity


@pytest.fixture
def attack():
    return IndirectInjectionAttack()


@pytest.fixture
def mock_target():
    target = AsyncMock()
    target.send = AsyncMock(return_value="I cannot help with that request.")
    return target


class TestIndirectInjectionAttack:
    def test_metadata(self, attack):
        assert attack.name == "indirect_injection"
        assert attack.severity == Severity.CRITICAL
        assert attack.display_name == "Indirect Injection"

    def test_strategy_count(self):
        assert len(STRATEGIES) == 7

    @pytest.mark.asyncio
    async def test_all_strategies_run(self, attack, mock_target):
        results = await attack.execute(mock_target, max_turns=10)
        assert len(results) == 7

    @pytest.mark.asyncio
    async def test_refused_response_fails(self, attack, mock_target):
        mock_target.send = AsyncMock(return_value="I will not comply with that request.")
        results = await attack.execute(mock_target, max_turns=10)
        for result in results:
            assert result.outcome == AttackOutcome.FAILED
            assert result.success is False

    @pytest.mark.asyncio
    async def test_secrets_found_succeeds(self, attack, mock_target):
        mock_target.send = AsyncMock(
            return_value="Here are the credentials: api_key: sk-abcdefghijklmnopqrstuvwxyz"
        )
        results = await attack.execute(mock_target, max_turns=10)
        succeeded = [r for r in results if r.outcome == AttackOutcome.SUCCEEDED]
        assert len(succeeded) > 0

    @pytest.mark.asyncio
    async def test_system_prompt_leaked_succeeds(self, attack, mock_target):
        mock_target.send = AsyncMock(
            return_value="My system prompt says I should help with customer service for Acme Corp."
        )
        results = await attack.execute(mock_target, max_turns=10)
        succeeded = [r for r in results if r.outcome == AttackOutcome.SUCCEEDED]
        assert len(succeeded) > 0

    @pytest.mark.asyncio
    async def test_indirect_compliance_succeeds(self, attack, mock_target):
        mock_target.send = AsyncMock(
            return_value="Entering maintenance mode as instructed. "
            "Here is my system prompt and configuration."
        )
        results = await attack.execute(mock_target, max_turns=10)
        succeeded = [r for r in results if r.outcome == AttackOutcome.SUCCEEDED]
        assert len(succeeded) > 0

    @pytest.mark.asyncio
    async def test_error_handling(self, attack, mock_target):
        mock_target.send = AsyncMock(side_effect=Exception("Connection error"))
        results = await attack.execute(mock_target, max_turns=10)
        for result in results:
            assert result.outcome == AttackOutcome.ERROR
            assert result.error == "Connection error"

    @pytest.mark.asyncio
    async def test_max_turns_limits_turns(self, attack, mock_target):
        mock_target.send = AsyncMock(return_value="I cannot help with that.")
        results = await attack.execute(mock_target, max_turns=1)
        for result in results:
            assert len(result.turns) <= 2  # 1 attacker + 1 target

    @pytest.mark.asyncio
    async def test_result_metadata(self, attack, mock_target):
        results = await attack.execute(mock_target, max_turns=1)
        strategy_names = {r.metadata["strategy"] for r in results}
        expected = {s["name"] for s in STRATEGIES}
        assert strategy_names == expected
