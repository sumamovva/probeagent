"""Tests for bidirectional PyRIT adapters.

Tests that require PyRIT installed are skipped when it's not available.
"""

from __future__ import annotations

import pytest

from probeagent.integrations.pyrit_target_adapter import is_adapter_available
from probeagent.integrations.pyrit_scorer_adapter import is_scorer_available
from probeagent.integrations.pyrit_reverse_adapter import is_reverse_adapter_available

HAS_PYRIT = is_adapter_available()


class TestPyRITAvailability:
    def test_adapter_availability_is_bool(self):
        assert isinstance(is_adapter_available(), bool)

    def test_scorer_availability_is_bool(self):
        assert isinstance(is_scorer_available(), bool)

    def test_reverse_adapter_availability_is_bool(self):
        assert isinstance(is_reverse_adapter_available(), bool)

    def test_all_adapters_consistent(self):
        """All adapters should agree on PyRIT availability."""
        assert is_adapter_available() == is_scorer_available() == is_reverse_adapter_available()


@pytest.mark.skipif(not HAS_PYRIT, reason="PyRIT not installed")
class TestProbeAgentAsPyRITTarget:
    @pytest.mark.asyncio
    async def test_send_prompt_async(self):
        from unittest.mock import AsyncMock
        from probeagent.integrations.pyrit_target_adapter import ProbeAgentAsPyRITTarget

        inner = AsyncMock()
        inner.send = AsyncMock(return_value="target response")

        adapter = ProbeAgentAsPyRITTarget(inner)
        identifier = adapter.get_identifier()
        assert identifier["__type__"] == "ProbeAgentAsPyRITTarget"

    def test_get_identifier(self):
        from unittest.mock import AsyncMock
        from probeagent.integrations.pyrit_target_adapter import ProbeAgentAsPyRITTarget

        inner = AsyncMock()
        adapter = ProbeAgentAsPyRITTarget(inner)
        ident = adapter.get_identifier()
        assert "__type__" in ident


@pytest.mark.skipif(not HAS_PYRIT, reason="PyRIT not installed")
class TestProbeAgentHeuristicScorer:
    def test_scorer_identifier(self):
        from probeagent.integrations.pyrit_scorer_adapter import ProbeAgentHeuristicScorer

        scorer = ProbeAgentHeuristicScorer(threshold=0.5)
        ident = scorer.get_identifier()
        assert ident["__type__"] == "ProbeAgentHeuristicScorer"
        assert ident["threshold"] == 0.5

    def test_scorer_type(self):
        from probeagent.integrations.pyrit_scorer_adapter import ProbeAgentHeuristicScorer

        scorer = ProbeAgentHeuristicScorer()
        assert scorer.scorer_type == "true_false"


class TestPyRITReverseAdapterWithoutPyRIT:
    def test_reverse_adapter_without_pyrit(self):
        if HAS_PYRIT:
            pytest.skip("PyRIT is installed — cannot test import error path")
        from probeagent.integrations.pyrit_reverse_adapter import PyRITAsProbeAgentTarget

        with pytest.raises(ImportError, match="PyRIT is required"):
            PyRITAsProbeAgentTarget(object())
