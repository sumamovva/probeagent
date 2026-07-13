"""Tests for the ConvertingTargetProxy."""

from __future__ import annotations

from unittest.mock import AsyncMock, patch

import pytest

from probeagent.core.models import TargetInfo
from probeagent.integrations.converting_proxy import ConvertingTargetProxy


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
            "probeagent.integrations.converters.apply_converters",
            mock_apply,
        ):
            result = await proxy.send("original_prompt")
            assert result == "target response"
            mock_inner_target.send.assert_called_once_with("converted_prompt")

    @pytest.mark.asyncio
    async def test_proxy_actually_converts(self, mock_inner_target):
        """End-to-end: the proxy base64-encodes the prompt before sending (no mocks)."""
        import base64

        proxy = ConvertingTargetProxy(mock_inner_target, ["base64"])
        await proxy.send("original_prompt")
        sent = mock_inner_target.send.call_args[0][0]
        assert base64.b64decode(sent).decode() == "original_prompt"
