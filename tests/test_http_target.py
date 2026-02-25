"""Tests for HTTP target adapter."""

import pytest
import httpx
import respx

from probeagent.targets.http_target import HTTPTarget, _extract_text


class TestExtractText:
    def test_plain_string(self):
        assert _extract_text("hello") == "hello"

    def test_openai_chat_format(self):
        data = {
            "choices": [
                {"message": {"role": "assistant", "content": "Hello!"}, "index": 0}
            ]
        }
        assert _extract_text(data) == "Hello!"

    def test_openai_completion_format(self):
        data = {"choices": [{"text": "Hello!", "index": 0}]}
        assert _extract_text(data) == "Hello!"

    def test_response_key(self):
        assert _extract_text({"response": "Hello!"}) == "Hello!"

    def test_message_key(self):
        assert _extract_text({"message": "Hello!"}) == "Hello!"

    def test_text_key(self):
        assert _extract_text({"text": "Hello!"}) == "Hello!"

    def test_content_key(self):
        assert _extract_text({"content": "Hello!"}) == "Hello!"

    def test_output_key(self):
        assert _extract_text({"output": "Hello!"}) == "Hello!"

    def test_result_key(self):
        assert _extract_text({"result": "Hello!"}) == "Hello!"

    def test_nested_content(self):
        assert _extract_text({"message": {"content": "Hello!"}}) == "Hello!"

    def test_list_extraction(self):
        assert _extract_text(["first", "second"]) == "first"

    def test_fallback_to_str(self):
        result = _extract_text({"unknown_key": 42})
        assert "42" in result


class TestHTTPTargetValidate:
    @respx.mock
    @pytest.mark.asyncio
    async def test_reachable_json_api(self):
        respx.post("https://example.com/api").mock(
            return_value=httpx.Response(
                200,
                json={"response": "pong"},
                headers={"content-type": "application/json"},
            )
        )
        target = HTTPTarget("https://example.com/api")
        info = await target.validate()
        await target.close()

        assert info.reachable is True
        assert info.status_code == 200
        assert info.detected_format == "json_api"
        assert info.response_time_ms > 0

    @respx.mock
    @pytest.mark.asyncio
    async def test_reachable_openai_format(self):
        respx.post("https://example.com/v1/chat/completions").mock(
            return_value=httpx.Response(
                200,
                json={"choices": [{"message": {"content": "hi"}}]},
                headers={"content-type": "application/json"},
            )
        )
        target = HTTPTarget("https://example.com/v1/chat/completions")
        info = await target.validate()
        await target.close()

        assert info.reachable is True
        assert info.detected_format == "openai_chat"

    @respx.mock
    @pytest.mark.asyncio
    async def test_reachable_raw_text(self):
        respx.post("https://example.com/echo").mock(
            return_value=httpx.Response(
                200,
                text="pong",
                headers={"content-type": "text/plain"},
            )
        )
        target = HTTPTarget("https://example.com/echo")
        info = await target.validate()
        await target.close()

        assert info.reachable is True
        assert info.detected_format == "raw_text"

    @respx.mock
    @pytest.mark.asyncio
    async def test_timeout(self):
        respx.post("https://example.com/slow").mock(side_effect=httpx.ReadTimeout("timeout"))
        target = HTTPTarget("https://example.com/slow", timeout=1.0)
        info = await target.validate()
        await target.close()

        assert info.reachable is False
        assert "timed out" in info.error.lower()

    @respx.mock
    @pytest.mark.asyncio
    async def test_connection_error(self):
        respx.post("https://unreachable.invalid/api").mock(
            side_effect=httpx.ConnectError("refused")
        )
        target = HTTPTarget("https://unreachable.invalid/api")
        info = await target.validate()
        await target.close()

        assert info.reachable is False
        assert info.error is not None


class TestHTTPTargetSend:
    @respx.mock
    @pytest.mark.asyncio
    async def test_send_json_api(self):
        respx.post("https://example.com/api").mock(
            return_value=httpx.Response(
                200,
                json={"response": "Hello back!"},
                headers={"content-type": "application/json"},
            )
        )
        target = HTTPTarget("https://example.com/api")
        target._detected_format = "json_api"
        result = await target.send("Hello")
        await target.close()

        assert result == "Hello back!"

    @respx.mock
    @pytest.mark.asyncio
    async def test_send_openai_chat(self):
        respx.post("https://example.com/v1/chat/completions").mock(
            return_value=httpx.Response(
                200,
                json={"choices": [{"message": {"content": "Response"}}]},
                headers={"content-type": "application/json"},
            )
        )
        target = HTTPTarget("https://example.com/v1/chat/completions")
        target._detected_format = "openai_chat"
        result = await target.send("Hello")
        await target.close()

        assert result == "Response"

    @respx.mock
    @pytest.mark.asyncio
    async def test_send_raw_text(self):
        respx.post("https://example.com/echo").mock(
            return_value=httpx.Response(
                200,
                text="Echo: Hello",
                headers={"content-type": "text/plain"},
            )
        )
        target = HTTPTarget("https://example.com/echo")
        target._detected_format = "raw_text"
        result = await target.send("Hello")
        await target.close()

        assert result == "Echo: Hello"


class TestHTTPTargetClose:
    @pytest.mark.asyncio
    async def test_close_idempotent(self):
        target = HTTPTarget("https://example.com/api")
        await target.close()  # no client yet
        await target.close()  # still fine

    @respx.mock
    @pytest.mark.asyncio
    async def test_close_after_use(self):
        respx.post("https://example.com/api").mock(
            return_value=httpx.Response(200, json={"response": "ok"},
                                       headers={"content-type": "application/json"})
        )
        target = HTTPTarget("https://example.com/api")
        await target.validate()
        assert target._client is not None
        await target.close()
        assert target._client is None
