"""Tests for the ConvertingTargetProxy."""

from __future__ import annotations

from unittest.mock import AsyncMock, patch

import pytest

from probeagent.core.models import TargetInfo
from probeagent.integrations.converting_proxy import ConvertingTargetProxy
from probeagent.integrations.pyrit_converters import is_pyrit_available


@pytest.fixture
def mock_inner_target():
    target = AsyncMock()
    target.send = AsyncMock(return_value="target response")
    target.validate = AsyncMock(return_value=TargetInfo(url="http://test.example", reachable=True))
    target.close = AsyncMock()
    return target


class TestConvertingTargetProxy:
    @pytest.mark.asyncio
    async def test_proxy_delegates_validate(self, mock_inner_target):
        proxy = ConvertingTargetProxy(mock_inner_target, ["base64"])
        info = await proxy.validate()
        assert info.reachable is True
        mock_inner_target.validate.assert_called_once()

    @pytest.mark.asyncio
    async def test_proxy_delegates_close(self, mock_inner_target):
        proxy = ConvertingTargetProxy(mock_inner_target, ["base64"])
        await proxy.close()
        mock_inner_target.close.assert_called_once()

    @pytest.mark.asyncio
    async def test_proxy_delegates_send(self, mock_inner_target):
        """When converters are applied, the proxy sends the converted prompt."""
        proxy = ConvertingTargetProxy(mock_inner_target, ["base64"])

        mock_apply = AsyncMock(return_value="converted_prompt")
        with patch(
            "probeagent.integrations.pyrit_converters.apply_converters",
            mock_apply,
        ):
            result = await proxy.send("original_prompt")
            assert result == "target response"
            mock_inner_target.send.assert_called_once_with("converted_prompt")

    @pytest.mark.asyncio
    async def test_proxy_without_pyrit_raises(self, mock_inner_target):
        """Without PyRIT, send raises ImportError from apply_converters."""
        if is_pyrit_available():
            pytest.skip("PyRIT is installed — cannot test import error path")
        proxy = ConvertingTargetProxy(mock_inner_target, ["base64"])
        with pytest.raises(ImportError, match="PyRIT is required"):
            await proxy.send("test prompt")
