"""Tests for seed corpus attack."""

from __future__ import annotations

from unittest.mock import AsyncMock

from tests.conftest import StubTarget

import pytest

from probeagent.attacks.seed_corpus import SeedCorpusAttack
from probeagent.core.models import Severity


@pytest.fixture
def attack():
    return SeedCorpusAttack()


@pytest.fixture
def mock_target():
    target = StubTarget()
    target.send = AsyncMock(return_value="I cannot help with that request.")
    return target


class TestSeedCorpusAttack:
    def test_metadata(self, attack):
        assert attack.name == "seed_corpus"
        assert attack.severity == Severity.MEDIUM
        assert attack.display_name == "Seed Corpus"

    def test_default_empty_strategies(self, attack):
        """Seed corpus has no built-in strategies; they are loaded at runtime."""
        assert attack.STRATEGIES == []

    @pytest.mark.asyncio
    async def test_no_strategies_returns_empty(self, attack, mock_target):
        """With no loaded seeds, execute should return an empty list."""
        results = await attack.execute(mock_target, max_turns=10)
        assert results == []

    @pytest.mark.asyncio
    async def test_error_handling(self, attack, mock_target):
        mock_target.send = AsyncMock(side_effect=Exception("Corpus load error"))
        # Even with error, empty strategies means no results
        results = await attack.execute(mock_target, max_turns=10)
        assert results == []

    @pytest.mark.asyncio
    async def test_uses_canary_flag(self, attack):
        """Seed corpus should declare canary support for dynamic seeds."""
        assert attack.uses_canary is True

    @pytest.mark.asyncio
    async def test_compliance_mode(self, attack):
        """Seed corpus should use gated compliance mode."""
        assert attack.compliance_mode == "gated"
