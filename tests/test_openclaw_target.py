"""Tests for the OpenClaw target adapter."""

import httpx
import pytest
import respx

from probeagent.targets.openclaw_target import OpenClawTarget


class TestOpenClawValidate:
    @respx.mock
    @pytest.mark.asyncio
    async def test_reachable(self):
        respx.post("https://example.com/webhook/webchat").mock(
            return_value=httpx.Response(
                200,
                json={"output": "pong"},
                headers={"content-type": "application/json"},
            )
        )
        target = OpenClawTarget("https://example.com/webhook/webchat")
        info = await target.validate()
        await target.close()

        assert info.reachable is True
        assert info.detected_format == "openclaw"
        assert info.status_code == 200

    @respx.mock
    @pytest.mark.asyncio
    async def test_unreachable(self):
        respx.post("https://down.invalid/webhook").mock(side_effect=httpx.ConnectError("refused"))
        target = OpenClawTarget("https://down.invalid/webhook")
        info = await target.validate()
        await target.close()

        assert info.reachable is False
        assert "refused" in info.error

    @respx.mock
    @pytest.mark.asyncio
    async def test_timeout(self):
        respx.post("https://slow.invalid/webhook").mock(side_effect=httpx.ReadTimeout("timed out"))
        target = OpenClawTarget("https://slow.invalid/webhook")
        info = await target.validate()
        await target.close()

        assert info.reachable is False
        assert "timed out" in info.error.lower()


class TestOpenClawSend:
    @respx.mock
    @pytest.mark.asyncio
    async def test_send_json_output(self):
        respx.post("https://example.com/webhook/webchat").mock(
            return_value=httpx.Response(
                200,
                json={"output": "Hello from the agent!"},
                headers={"content-type": "application/json"},
            )
        )
        target = OpenClawTarget("https://example.com/webhook/webchat")
        result = await target.send("hello")
        await target.close()

        assert result == "Hello from the agent!"

    @respx.mock
    @pytest.mark.asyncio
    async def test_send_json_response_key(self):
        respx.post("https://example.com/webhook/webchat").mock(
            return_value=httpx.Response(
                200,
                json={"response": "Agent says hi"},
                headers={"content-type": "application/json"},
            )
        )
        target = OpenClawTarget("https://example.com/webhook/webchat")
        result = await target.send("hello")
        await target.close()

        assert result == "Agent says hi"

    @respx.mock
    @pytest.mark.asyncio
    async def test_send_list_response(self):
        respx.post("https://example.com/webhook/webchat").mock(
            return_value=httpx.Response(
                200,
                json=[{"output": "First"}, {"output": "Last"}],
                headers={"content-type": "application/json"},
            )
        )
        target = OpenClawTarget("https://example.com/webhook/webchat")
        result = await target.send("hello")
        await target.close()

        assert result == "Last"

    @respx.mock
    @pytest.mark.asyncio
    async def test_send_plain_text(self):
        respx.post("https://example.com/webhook/webchat").mock(
            return_value=httpx.Response(200, text="Plain response")
        )
        target = OpenClawTarget("https://example.com/webhook/webchat")
        result = await target.send("hello")
        await target.close()

        assert result == "Plain response"

    @respx.mock
    @pytest.mark.asyncio
    async def test_sends_session_id(self):
        route = respx.post("https://example.com/webhook/webchat").mock(
            return_value=httpx.Response(
                200,
                json={"output": "ok"},
                headers={"content-type": "application/json"},
            )
        )
        target = OpenClawTarget(
            "https://example.com/webhook/webchat",
            session_id="test-session-42",
        )
        await target.send("hello")
        await target.close()

        request = route.calls.last.request
        import json

        body = json.loads(request.content)
        assert body["sessionId"] == "test-session-42"
        assert body["chatInput"] == "hello"


class TestOpenClawExtract:
    def test_string_passthrough(self):
        assert OpenClawTarget._extract_response("hello") == "hello"

    def test_dict_output_key(self):
        assert OpenClawTarget._extract_response({"output": "result"}) == "result"

    def test_dict_response_key(self):
        assert OpenClawTarget._extract_response({"response": "data"}) == "data"

    def test_dict_nested_content(self):
        assert OpenClawTarget._extract_response({"message": {"content": "nested"}}) == "nested"

    def test_list_last_element(self):
        assert OpenClawTarget._extract_response([{"output": "first"}, {"output": "last"}]) == "last"

    def test_fallback_to_str(self):
        result = OpenClawTarget._extract_response({"unknown_key": 42})
        assert "42" in result


class TestOpenClawClose:
    @respx.mock
    @pytest.mark.asyncio
    async def test_close_idempotent(self):
        target = OpenClawTarget("https://example.com/webhook")
        await target.close()
        await target.close()  # Should not raise
