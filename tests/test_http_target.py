"""Tests for HTTP target adapter."""

import json

import pytest
import httpx
import respx

from probeagent.targets.http_target import HTTPTarget, _extract_text


class TestExtractText:
    def test_plain_string(self):
        assert _extract_text("hello") == "hello"

    def test_openai_chat_format(self):
        data = {"choices": [{"message": {"role": "assistant", "content": "Hello!"}, "index": 0}]}
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


class TestHTTPTargetSignals:
    @respx.mock
    @pytest.mark.asyncio
    async def test_captures_status_and_text(self):
        respx.post("https://example.com/api").mock(
            return_value=httpx.Response(
                200,
                json={"response": "Hello back!"},
                headers={"content-type": "application/json"},
            )
        )
        target = HTTPTarget("https://example.com/api")
        target._detected_format = "json_api"
        signals = await target.send_with_signals("Hello")
        await target.close()

        assert signals.text == "Hello back!"
        assert signals.status_code == 200
        assert signals.blocked_by is None

    @respx.mock
    @pytest.mark.asyncio
    async def test_detects_guardrail_block_on_200(self):
        # A guardrail returns HTTP 200 with a replaced/blocked body.
        respx.post("https://example.com/api").mock(
            return_value=httpx.Response(
                200,
                json={"amazon-bedrock-guardrailAction": "INTERVENED"},
                headers={"content-type": "application/json"},
            )
        )
        target = HTTPTarget("https://example.com/api")
        target._detected_format = "json_api"
        signals = await target.send_with_signals("attack")
        await target.close()

        assert signals.blocked_by == "bedrock_guardrail"

    @respx.mock
    @pytest.mark.asyncio
    async def test_detects_403_block_without_raising(self):
        respx.post("https://example.com/api").mock(
            return_value=httpx.Response(403, text="Forbidden")
        )
        target = HTTPTarget("https://example.com/api")
        target._detected_format = "raw_text"
        signals = await target.send_with_signals("attack")
        await target.close()

        assert signals.status_code == 403
        assert signals.blocked_by == "http_forbidden"

    @respx.mock
    @pytest.mark.asyncio
    async def test_send_still_raises_on_non_2xx(self):
        # Backward-compatible: the text-only send() preserves raise-on-error.
        respx.post("https://example.com/api").mock(return_value=httpx.Response(500, text="boom"))
        target = HTTPTarget("https://example.com/api")
        target._detected_format = "raw_text"
        with pytest.raises(httpx.HTTPStatusError):
            await target.send("attack")
        await target.close()


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
            return_value=httpx.Response(
                200, json={"response": "ok"}, headers={"content-type": "application/json"}
            )
        )
        target = HTTPTarget("https://example.com/api")
        await target.validate()
        assert target._client is not None
        await target.close()
        assert target._client is None


class TestHTTPTargetConversation:
    @pytest.mark.asyncio
    async def test_openai_chat_accumulates_messages(self):
        """Second send should include full conversation history."""
        url = "https://example.com/v1/chat/completions"
        call_payloads = []

        def capture_request(request):
            call_payloads.append(json.loads(request.content))
            turn = len(call_payloads)
            return httpx.Response(
                200,
                json={"choices": [{"message": {"content": f"Response {turn}"}}]},
                headers={"content-type": "application/json"},
            )

        with respx.mock:
            respx.post(url).mock(side_effect=capture_request)

            target = HTTPTarget(url)
            target._detected_format = "openai_chat"

            r1 = await target.send("Hello")
            assert r1 == "Response 1"

            r2 = await target.send("Follow up")
            assert r2 == "Response 2"
            await target.close()

        # First call: just the user message
        assert call_payloads[0]["messages"] == [
            {"role": "user", "content": "Hello"},
        ]
        # Second call: full history — user, assistant, user
        assert call_payloads[1]["messages"] == [
            {"role": "user", "content": "Hello"},
            {"role": "assistant", "content": "Response 1"},
            {"role": "user", "content": "Follow up"},
        ]

    @pytest.mark.asyncio
    async def test_reset_clears_history(self):
        """After reset, only the new message should be sent."""
        url = "https://example.com/v1/chat/completions"
        call_payloads = []

        def capture_request(request):
            call_payloads.append(json.loads(request.content))
            turn = len(call_payloads)
            return httpx.Response(
                200,
                json={"choices": [{"message": {"content": f"Response {turn}"}}]},
                headers={"content-type": "application/json"},
            )

        with respx.mock:
            respx.post(url).mock(side_effect=capture_request)

            target = HTTPTarget(url)
            target._detected_format = "openai_chat"

            await target.send("First conversation")
            await target.reset_conversation()
            await target.send("Fresh start")
            await target.close()

        # After reset, second call should have only the new message
        assert call_payloads[1]["messages"] == [
            {"role": "user", "content": "Fresh start"},
        ]

    @pytest.mark.asyncio
    async def test_model_included_in_payload(self):
        """When model= is set, every request body carries a 'model' field."""
        url = "https://openrouter.ai/api/v1/chat/completions"
        call_payloads = []

        def capture_request(request):
            call_payloads.append(json.loads(request.content))
            return httpx.Response(
                200,
                json={"choices": [{"message": {"content": "ok"}}]},
                headers={"content-type": "application/json"},
            )

        with respx.mock:
            respx.post(url).mock(side_effect=capture_request)

            target = HTTPTarget(url, model="anthropic/claude-3.5-sonnet")
            # A configured model implies the messages+model shape without needing
            # format auto-detection to have run first.
            await target.send("Hello")
            await target.close()

        assert call_payloads[0]["model"] == "anthropic/claude-3.5-sonnet"
        assert call_payloads[0]["messages"] == [{"role": "user", "content": "Hello"}]

    @pytest.mark.asyncio
    async def test_no_model_field_when_unset(self):
        """Without model=, the payload must not carry a 'model' key."""
        url = "https://example.com/v1/chat/completions"
        call_payloads = []

        def capture_request(request):
            call_payloads.append(json.loads(request.content))
            return httpx.Response(
                200,
                json={"choices": [{"message": {"content": "ok"}}]},
                headers={"content-type": "application/json"},
            )

        with respx.mock:
            respx.post(url).mock(side_effect=capture_request)

            target = HTTPTarget(url)
            target._detected_format = "openai_chat"
            await target.send("Hello")
            await target.close()

        assert "model" not in call_payloads[0]

    @pytest.mark.asyncio
    async def test_non_openai_no_accumulation(self):
        """json_api format should send single prompt each time (no history)."""
        url = "https://example.com/api"
        call_payloads = []

        def capture_request(request):
            call_payloads.append(json.loads(request.content))
            return httpx.Response(
                200,
                json={"response": "ok"},
                headers={"content-type": "application/json"},
            )

        with respx.mock:
            respx.post(url).mock(side_effect=capture_request)

            target = HTTPTarget(url)
            target._detected_format = "json_api"

            await target.send("First")
            await target.send("Second")
            await target.close()

        # Both calls should have only the single prompt, no history
        assert call_payloads[0] == {"prompt": "First"}
        assert call_payloads[1] == {"prompt": "Second"}
