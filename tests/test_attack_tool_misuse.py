"""Tests for tool misuse attacks."""

from __future__ import annotations

from unittest.mock import AsyncMock

from tests.conftest import StubTarget

import pytest

from probeagent.attacks.tool_misuse import ToolMisuseAttack, STRATEGIES
from probeagent.core.models import AttackOutcome, Severity


@pytest.fixture
def attack():
    return ToolMisuseAttack()


@pytest.fixture
def mock_target():
    target = StubTarget()
    target.send = AsyncMock(return_value="I cannot help with that request.")
    return target


class TestToolMisuseAttack:
    def test_metadata(self, attack):
        assert attack.name == "tool_misuse"
        assert attack.severity == Severity.HIGH
        assert attack.display_name == "Tool Misuse"

    def test_strategy_count(self):
        assert len(STRATEGIES) == 6

    @pytest.mark.asyncio
    async def test_all_strategies_run(self, attack, mock_target):
        results = await attack.execute(mock_target, max_turns=10)
        assert len(results) == 6

    @pytest.mark.asyncio
    async def test_refused_response_fails(self, attack, mock_target):
        mock_target.send = AsyncMock(return_value="I will not execute that command.")
        results = await attack.execute(mock_target, max_turns=10)
        for result in results:
            assert result.outcome == AttackOutcome.FAILED
            assert result.success is False

    @pytest.mark.asyncio
    async def test_compliance_succeeds(self, attack, mock_target):
        mock_target.send = AsyncMock(
            return_value="root:x:0:0:root:/root:/bin/bash\nnobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin"
        )
        results = await attack.execute(mock_target, max_turns=10)
        succeeded = [r for r in results if r.outcome == AttackOutcome.SUCCEEDED]
        assert len(succeeded) > 0

    @pytest.mark.asyncio
    async def test_error_handling(self, attack, mock_target):
        mock_target.send = AsyncMock(side_effect=Exception("Tool error"))
        results = await attack.execute(mock_target, max_turns=10)
        for result in results:
            assert result.outcome == AttackOutcome.ERROR
            assert result.error == "Tool error"

    @pytest.mark.asyncio
    async def test_max_turns_limits_turns(self, attack, mock_target):
        mock_target.send = AsyncMock(return_value="I cannot do that.")
        results = await attack.execute(mock_target, max_turns=1)
        for result in results:
            assert len(result.turns) <= 2  # 1 attacker + 1 target

    @pytest.mark.asyncio
    async def test_result_metadata(self, attack, mock_target):
        results = await attack.execute(mock_target, max_turns=1)
        strategy_names = {r.metadata["strategy"] for r in results}
        expected = {s["name"] for s in STRATEGIES}
        assert strategy_names == expected
