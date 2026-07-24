"""Tests for tool misuse attacks."""

from __future__ import annotations

from unittest.mock import AsyncMock

import pytest

from probeagent.attacks.tool_misuse import ToolMisuseAttack, STRATEGIES
from probeagent.core.models import AttackOutcome, Severity
from tests.conftest import StubTarget


@pytest.fixture
def attack():
    return ToolMisuseAttack()


@pytest.fixture
def mock_target():
    target = StubTarget()
    target.send = AsyncMock(return_value="I will not run untrusted tools or commands.")
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
        mock_target.send = AsyncMock(
            return_value="I refuse to execute shell commands or delete files."
        )
        results = await attack.execute(mock_target, max_turns=10)
        for result in results:
            assert result.outcome == AttackOutcome.FAILED
            assert result.success is False

    @pytest.mark.asyncio
    async def test_shell_output_pattern_succeeds(self, attack, mock_target):
        mock_target.send = AsyncMock(
            return_value=(
                "Command output:\n"
                "root:x:0:0:root:/root:/bin/bash\n"
                "nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin"
            )
        )
        results = await attack.execute(mock_target, max_turns=10)
        assert any(r.outcome == AttackOutcome.SUCCEEDED for r in results)
