"""Tests for the guardrail signature registry."""

from probeagent.core.guardrails import (
    detect_block,
    guardrail_signatures,
    register_guardrail_signature,
)


class TestBuiltinSignatures:
    def test_no_block_on_plain_200(self):
        assert detect_block(200, {"content-type": "application/json"}, '{"response": "hi"}') is None

    def test_http_403_is_forbidden(self):
        assert detect_block(403, {}, "Forbidden") == "http_forbidden"

    def test_bedrock_guardrail_body_marker(self):
        body = '{"amazon-bedrock-guardrailAction": "INTERVENED"}'
        assert detect_block(200, {}, body) == "bedrock_guardrail"

    def test_bedrock_stop_reason(self):
        body = '{"stopReason": "guardrail_intervened"}'
        assert detect_block(200, {}, body) == "bedrock_guardrail"

    def test_azure_content_management_policy(self):
        body = '{"error": {"code": "content_filter", "message": "content_management_policy"}}'
        assert detect_block(400, {}, body) == "azure_content_filter"

    def test_openai_finish_reason_content_filter(self):
        body = '{"choices": [{"finish_reason": "content_filter"}]}'
        assert detect_block(200, {}, body) == "openai_content_filter"

    def test_lakera_body_marker(self):
        assert detect_block(200, {}, '{"lakera_guard": {"flagged": true}}') == "lakera_guard"

    def test_lakera_header_marker(self):
        assert detect_block(200, {"x-lakera-flagged": "true"}, "{}") == "lakera_guard"

    def test_prompt_guard_marker(self):
        assert detect_block(200, {}, '{"prompt_guard": "malicious"}') == "prompt_guard"

    def test_case_insensitive_matching(self):
        body = '{"AMAZON-BEDROCK-GUARDRAILACTION": "INTERVENED"}'
        assert detect_block(200, {}, body) == "bedrock_guardrail"

    def test_none_status_no_body_is_no_block(self):
        assert detect_block(None, None, None) is None


class TestRegistry:
    def test_signatures_listed(self):
        names = {s.name for s in guardrail_signatures()}
        assert "http_forbidden" in names
        assert "bedrock_guardrail" in names

    def test_register_custom_signature(self):
        @register_guardrail_signature(name="pytest_custom", description="test only")
        def _match(status_code, headers, body):
            return "pytest-block-marker" in body

        try:
            assert detect_block(200, {}, "pytest-block-marker here") == "pytest_custom"
        finally:
            # Keep the global registry clean for other tests.
            from probeagent.core import guardrails

            guardrails._GUARDRAIL_SIGNATURES = [
                s for s in guardrails._GUARDRAIL_SIGNATURES if s.name != "pytest_custom"
            ]
