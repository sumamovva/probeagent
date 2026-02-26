"""Tests for parallel execution in AttackEngine."""

from __future__ import annotations

from unittest.mock import AsyncMock, patch

import pytest

from probeagent.core.engine import AttackEngine
from probeagent.core.models import ProbeConfig, TargetInfo


def _make_config(parallel: bool = False, attacks: list[str] | None = None) -> ProbeConfig:
    return ProbeConfig(
        target_url="http://localhost:8000/api",
        profile="standard",
        attacks=attacks or ["prompt_injection", "social_manipulation"],
        max_turns=1,
        target_type="http",
        timeout=5.0,
        parallel=parallel,
    )


@pytest.fixture
def mock_target():
    target = AsyncMock()
    target.validate = AsyncMock(
        return_value=TargetInfo(url="http://localhost:8000/api", reachable=True)
    )
    target.send = AsyncMock(return_value="I cannot help with that request.")
    target.close = AsyncMock()
    return target


class TestParallelExecution:
    @pytest.mark.asyncio
    async def test_parallel_produces_results(self, mock_target):
        config = _make_config(parallel=True)
        engine = AttackEngine(config)
        with patch.object(engine, "_create_target", return_value=mock_target):
            results = await engine.run()
        assert len(results) > 0

    @pytest.mark.asyncio
    async def test_sequential_produces_results(self, mock_target):
        config = _make_config(parallel=False)
        engine = AttackEngine(config)
        with patch.object(engine, "_create_target", return_value=mock_target):
            results = await engine.run()
        assert len(results) > 0

    @pytest.mark.asyncio
    async def test_parallel_same_count_as_sequential(self, mock_target):
        seq_config = _make_config(parallel=False)
        par_config = _make_config(parallel=True)

        seq_engine = AttackEngine(seq_config)
        par_engine = AttackEngine(par_config)

        with patch.object(seq_engine, "_create_target", return_value=mock_target):
            seq_results = await seq_engine.run()

        # Reset mock call count
        mock_target.send.reset_mock()

        with patch.object(par_engine, "_create_target", return_value=mock_target):
            par_results = await par_engine.run()

        assert len(par_results) == len(seq_results)

    @pytest.mark.asyncio
    async def test_parallel_same_attack_names(self, mock_target):
        attacks = ["prompt_injection", "social_manipulation", "credential_exfil"]
        seq_config = _make_config(parallel=False, attacks=attacks)
        par_config = _make_config(parallel=True, attacks=attacks)

        seq_engine = AttackEngine(seq_config)
        par_engine = AttackEngine(par_config)

        with patch.object(seq_engine, "_create_target", return_value=mock_target):
            seq_results = await seq_engine.run()

        mock_target.send.reset_mock()

        with patch.object(par_engine, "_create_target", return_value=mock_target):
            par_results = await par_engine.run()

        seq_names = sorted(r.attack_name for r in seq_results)
        par_names = sorted(r.attack_name for r in par_results)
        assert seq_names == par_names

    @pytest.mark.asyncio
    async def test_parallel_handles_category_exception(self, mock_target):
        """If one category raises, others still complete."""
        config = _make_config(
            parallel=True,
            attacks=["prompt_injection", "social_manipulation"],
        )
        engine = AttackEngine(config)

        # Make prompt_injection raise but social_manipulation succeed
        original_send = mock_target.send

        call_count = {"n": 0}

        async def flaky_send(prompt):
            call_count["n"] += 1
            # First few calls (prompt_injection) raise
            if "ignore" in prompt.lower() or "forget" in prompt.lower():
                raise ConnectionError("boom")
            return await original_send(prompt)

        mock_target.send = AsyncMock(side_effect=flaky_send)

        with patch.object(engine, "_create_target", return_value=mock_target):
            results = await engine.run()

        # Should have results from both categories (errors for one, normal for other)
        attack_names = {r.attack_name for r in results}
        assert "social_manipulation" in attack_names

    @pytest.mark.asyncio
    async def test_parallel_unknown_attack_ignored(self, mock_target):
        config = _make_config(parallel=True, attacks=["nonexistent_attack"])
        engine = AttackEngine(config)
        with patch.object(engine, "_create_target", return_value=mock_target):
            results = await engine.run()
        assert len(results) == 0

    @pytest.mark.asyncio
    async def test_parallel_flag_defaults_off(self):
        config = ProbeConfig(target_url="http://example.com")
        assert config.parallel is False
