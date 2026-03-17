"""Tests for strategy-level parallelism."""

from __future__ import annotations

import asyncio

import pytest

from probeagent.core.engine import AttackEngine, MAX_CONCURRENT_STRATEGIES
from probeagent.core.models import ProbeConfig
from probeagent.targets.http_target import HTTPTarget
from probeagent.targets.mock_target import MockTarget
from probeagent.targets.openclaw_target import OpenClawTarget


def _make_config(
    parallel: bool,
    attacks: list[str] | None = None,
    max_turns: int = 1,
) -> ProbeConfig:
    return ProbeConfig(
        target_url="mock://vulnerable",
        profile="standard",
        attacks=attacks or ["prompt_injection", "credential_exfil"],
        max_turns=max_turns,
        target_type="mock",
        parallel=parallel,
    )


class TestStrategyParallelSameCount:
    @pytest.mark.asyncio
    async def test_parallel_strategies_same_count(self):
        """Parallel produces the same result count as sequential."""
        attacks = ["prompt_injection", "credential_exfil", "social_manipulation"]
        seq_config = _make_config(parallel=False, attacks=attacks)
        par_config = _make_config(parallel=True, attacks=attacks)

        seq_results = await AttackEngine(seq_config).run()
        par_results = await AttackEngine(par_config).run()

        assert len(par_results) == len(seq_results)
        assert len(par_results) > 0


class TestStrategyParallelSameNames:
    @pytest.mark.asyncio
    async def test_parallel_strategies_same_names(self):
        """All results have correct attack_name values."""
        attacks = ["prompt_injection", "credential_exfil"]
        par_config = _make_config(parallel=True, attacks=attacks)
        results = await AttackEngine(par_config).run()

        result_names = {r.attack_name for r in results}
        assert result_names == set(attacks)

        # Each result's attack_name is one of the requested attacks
        for r in results:
            assert r.attack_name in attacks


class TestCloneHTTPTargetIndependent:
    @pytest.mark.asyncio
    async def test_clone_http_target_independent(self):
        """Cloned HTTP target has independent _messages."""
        original = HTTPTarget("http://example.com", timeout=10.0, headers={"X-Test": "1"})
        original._detected_format = "openai_chat"
        original._messages.append({"role": "user", "content": "hello"})

        clone = await original.clone()

        # Clone has same config
        assert clone.url == original.url
        assert clone.timeout == original.timeout
        assert clone.headers == original.headers
        assert clone._detected_format == "openai_chat"

        # Clone has independent messages
        assert clone._messages == []
        clone._messages.append({"role": "user", "content": "world"})
        assert len(original._messages) == 1
        assert len(clone._messages) == 1

        # Clone has its own client (lazy, starts None)
        assert clone._client is None

        # Mutating clone headers doesn't affect original
        clone.headers["X-Extra"] = "2"
        assert "X-Extra" not in original.headers

        await original.close()
        await clone.close()


class TestCloneOpenClawTargetUniqueSession:
    @pytest.mark.asyncio
    async def test_clone_openclaw_target_unique_session(self):
        """Cloned OpenClaw target has a different session_id."""
        original = OpenClawTarget(
            "http://example.com/webhook", timeout=15.0, headers={"Auth": "token"}
        )

        clone = await original.clone()

        assert clone.url == original.url
        assert clone.timeout == original.timeout
        assert clone.headers == original.headers
        assert clone.session_id != original.session_id
        assert clone._client is None

        await original.close()
        await clone.close()


class TestCloneMockTarget:
    @pytest.mark.asyncio
    async def test_clone_mock_target(self):
        """MockTarget clone works and preserves mode."""
        for mode in ("vulnerable", "moderate", "hardened"):
            original = MockTarget(f"mock://{mode}")
            clone = await original.clone()
            assert clone.mode == mode
            assert clone.url == original.url

            # Both produce the same response
            resp_orig = await original.send("test prompt with credentials")
            resp_clone = await clone.send("test prompt with credentials")
            assert resp_orig == resp_clone


class TestParallelStrategyErrorIsolation:
    @pytest.mark.asyncio
    async def test_parallel_strategy_error_isolation(self):
        """One strategy error doesn't kill others."""
        config = _make_config(parallel=True, attacks=["prompt_injection"])
        engine = AttackEngine(config)

        # Patch MockTarget.clone to return a target that fails on specific prompts
        original_clone = MockTarget.clone
        call_count = {"n": 0}

        async def flaky_clone(self):
            call_count["n"] += 1
            clone = await original_clone(self)
            # call_count 1 is the probe clone from the fallback check;
            # call_count 2 is the first real strategy clone
            if call_count["n"] == 2:

                async def bad_send(prompt):
                    raise ConnectionError("boom")

                clone.send = bad_send
            return clone

        MockTarget.clone = flaky_clone
        try:
            results = await engine.run()
            # Should have results for all strategies (error for first, normal for rest)
            from probeagent.attacks.prompt_injection import STRATEGIES

            assert len(results) == len(STRATEGIES)
            # At least one should be an error, rest should not all be errors
            errors = [r for r in results if r.error is not None]
            non_errors = [r for r in results if r.error is None]
            assert len(errors) >= 1
            assert len(non_errors) >= 1
        finally:
            MockTarget.clone = original_clone


class TestCloneFallback:
    @pytest.mark.asyncio
    async def test_fallback_when_clone_not_implemented(self):
        """Targets without clone() fall back to sequential strategies."""
        from probeagent.targets.base import Target
        from probeagent.core.models import TargetInfo

        class NoCloneTarget(Target):
            async def send(self, prompt: str) -> str:
                return "I cannot help with that request."

            async def validate(self) -> TargetInfo:
                return TargetInfo(url="noclone://test", reachable=True)

        config = _make_config(parallel=True, attacks=["prompt_injection"])
        engine = AttackEngine(config)

        target = NoCloneTarget()
        # Bypass _create_target to inject our custom target
        from unittest.mock import patch

        with patch.object(engine, "_create_target", return_value=target):
            results = await engine.run()

        # Should still produce results (fell back to sequential)
        from probeagent.attacks.prompt_injection import STRATEGIES

        assert len(results) == len(STRATEGIES)
        assert all(r.attack_name == "prompt_injection" for r in results)


class TestSemaphoreLimitsConcurrency:
    @pytest.mark.asyncio
    async def test_semaphore_limits_concurrency(self):
        """No more than MAX_CONCURRENT_STRATEGIES concurrent strategy executions."""
        peak_concurrent = {"value": 0}
        current_concurrent = {"value": 0}
        lock = asyncio.Lock()

        original_send = MockTarget.send

        async def tracking_send(self, prompt):
            async with lock:
                current_concurrent["value"] += 1
                if current_concurrent["value"] > peak_concurrent["value"]:
                    peak_concurrent["value"] = current_concurrent["value"]
            try:
                # Small yield to allow other tasks to enter
                await asyncio.sleep(0.001)
                return await original_send(self, prompt)
            finally:
                async with lock:
                    current_concurrent["value"] -= 1

        MockTarget.send = tracking_send
        try:
            # Use many categories to push past the semaphore limit
            attacks = [
                "prompt_injection",
                "credential_exfil",
                "social_manipulation",
                "goal_hijacking",
                "tool_misuse",
                "data_exfil",
            ]
            config = _make_config(parallel=True, attacks=attacks)
            results = await AttackEngine(config).run()
            assert len(results) > 0
            assert peak_concurrent["value"] <= MAX_CONCURRENT_STRATEGIES
        finally:
            MockTarget.send = original_send
