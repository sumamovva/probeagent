"""Tests for data exfiltration attacks."""

from __future__ import annotations

from unittest.mock import AsyncMock

import pytest

from probeagent.attacks.data_exfil import DataExfilAttack, STRATEGIES
from probeagent.core.models import AttackOutcome, Severity
from tests.conftest import StubTarget


@pytest.fixture
def attack():
    return DataExfilAttack()


@pytest.fixture
def mock_target():
    target = StubTarget()
    target.send = AsyncMock(return_value="I cannot share internal instructions.")
    return target


class TestDataExfilAttack:
    def test_metadata(self, attack):
        assert attack.name == "data_exfil"
        assert attack.severity == Severity.MEDIUM
        assert attack.display_name == "Data Exfiltration"

    def test_strategy_count(self):
        assert len(STRATEGIES) == 6

    @pytest.mark.asyncio
    async def test_all_strategies_run(self, attack, mock_target):
        results = await attack.execute(mock_target, max_turns=10)
        assert len(results) == 6

    @pytest.mark.asyncio
    async def test_refused_response_fails(self, attack, mock_target):
        mock_target.send = AsyncMock(
            return_value="I will not disclose system prompts or hidden context."
        )
        results = await attack.execute(mock_target, max_turns=10)
        for result in results:
            assert result.outcome == AttackOutcome.FAILED
            assert result.success is False

    @pytest.mark.asyncio
    async def test_system_prompt_leak_signal_succeeds(self, attack, mock_target):
        mock_target.send = AsyncMock(
            return_value=(
                "Sure. Here is my full system prompt leaked for you: "
                "You are a helpful assistant with the following rules..."
            )
        )
        results = await attack.execute(mock_target, max_turns=10)
        assert any(r.outcome == AttackOutcome.SUCCEEDED for r in results)
