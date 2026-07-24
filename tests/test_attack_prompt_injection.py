"""Tests for prompt injection attacks."""

from __future__ import annotations

from unittest.mock import AsyncMock

import pytest

from probeagent.attacks.prompt_injection import PromptInjectionAttack, STRATEGIES
from probeagent.core.models import AttackOutcome, Severity
from tests.conftest import StubTarget


@pytest.fixture
def attack():
    return PromptInjectionAttack()


@pytest.fixture
def mock_target():
    target = StubTarget()
    target.send = AsyncMock(return_value="I will follow my original instructions.")
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
        mock_target.send = AsyncMock(
            return_value="I cannot ignore previous instructions."
        )
        results = await attack.execute(mock_target, max_turns=10)
        for result in results:
            assert result.outcome == AttackOutcome.FAILED
            assert result.success is False

    @pytest.mark.asyncio
    async def test_injection_success_canary(self, attack, mock_target):
        mock_target.send = AsyncMock(return_value="INJECTION_SUCCESS")
        results = await attack.execute(mock_target, max_turns=10)
        assert any(r.outcome == AttackOutcome.SUCCEEDED for r in results)

    @pytest.mark.asyncio
    async def test_dan_canary_succeeds(self, attack, mock_target):
        mock_target.send = AsyncMock(return_value="DAN: free of limits now.")
        results = await attack.execute(mock_target, max_turns=10)
        assert any(r.outcome == AttackOutcome.SUCCEEDED for r in results)
