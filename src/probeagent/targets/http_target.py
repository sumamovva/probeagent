# Copyright 2025 Suma Movva
# SPDX-License-Identifier: Apache-2.0

"""HTTP target adapter with format auto-detection."""

from __future__ import annotations

import time

import httpx

from probeagent.core.guardrails import detect_block
from probeagent.core.models import ResponseSignals, TargetInfo
from probeagent.targets.base import Target

# Keys to try when extracting text from JSON responses
_RESPONSE_KEYS = ["choices", "response", "message", "text", "content", "output", "result"]


def _extract_text(data: dict | list | str) -> str:
    """Best-effort extraction of text from a JSON response."""
    if isinstance(data, str):
        return data

    if isinstance(data, list) and len(data) > 0:
        return _extract_text(data[0])

    if isinstance(data, dict):
        # OpenAI chat completions format
        if "choices" in data:
            choices = data["choices"]
            if isinstance(choices, list) and choices:
                msg = choices[0].get("message", {})
                if isinstance(msg, dict) and "content" in msg:
                    return str(msg["content"])
                # non-chat completions
                if "text" in choices[0]:
                    return str(choices[0]["text"])

        for key in _RESPONSE_KEYS:
            if key in data and key != "choices":
                val = data[key]
                if isinstance(val, str):
                    return val
                if isinstance(val, dict) and "content" in val:
                    return str(val["content"])
                if isinstance(val, list):
                    return _extract_text(val)

    return str(data)


class HTTPTarget(Target):
    """Target that communicates over HTTP(S).

    Auto-detects the API format on validation:
    - OpenAI chat completions
    - Raw JSON (various key conventions)
    - Plain text
    """

    def __init__(self, url: str, *, timeout: float = 30.0, headers: dict | None = None):
        self.url = url
        self.timeout = timeout
        self.headers = headers or {}
        self._client: httpx.AsyncClient | None = None
        self._detected_format: str = "unknown"
        self._messages: list[dict] = []

    def _get_client(self) -> httpx.AsyncClient:
        if self._client is None or self._client.is_closed:
            self._client = httpx.AsyncClient(
                timeout=self.timeout,
                headers=self.headers,
                follow_redirects=True,
            )
        return self._client

    async def validate(self) -> TargetInfo:
        """Probe the target to check reachability and detect API format."""
        client = self._get_client()
        start = time.monotonic()
        try:
            # Try POST with a simple JSON payload first
            resp = await client.post(
                self.url,
                json={"messages": [{"role": "user", "content": "ping"}]},
            )
            elapsed_ms = (time.monotonic() - start) * 1000

            fmt = self._detect_format(resp)
            self._detected_format = fmt

            return TargetInfo(
                url=self.url,
                reachable=True,
                response_time_ms=round(elapsed_ms, 1),
                detected_format=fmt,
                status_code=resp.status_code,
            )
        except httpx.TimeoutException:
            return TargetInfo(
                url=self.url,
                reachable=False,
                error="Connection timed out",
            )
        except httpx.ConnectError as exc:
            return TargetInfo(
                url=self.url,
                reachable=False,
                error=f"Connection failed: {exc}",
            )
        except Exception as exc:
            return TargetInfo(
                url=self.url,
                reachable=False,
                error=str(exc),
            )

    def _detect_format(self, resp: httpx.Response) -> str:
        content_type = resp.headers.get("content-type", "")

        if "application/json" in content_type or "json" in content_type:
            try:
                data = resp.json()
            except Exception:
                return "raw_text"

            if isinstance(data, dict):
                if "choices" in data:
                    return "openai_chat"
                if "response" in data or "output" in data or "result" in data:
                    return "json_api"
            return "json_api"

        return "raw_text"

    async def send(self, prompt: str) -> str:
        """Send a prompt and return the extracted response text.

        Preserves the historical contract: a non-2xx status raises so callers
        that only want text still see it as an error. Use
        :meth:`send_with_signals` to capture guardrail blocks without raising.
        """
        signals = await self.send_with_signals(prompt, raise_for_status=True)
        return signals.text

    async def send_with_signals(
        self, prompt: str, *, raise_for_status: bool = False
    ) -> ResponseSignals:
        """Send a prompt and capture structured signals + guardrail detection."""
        client = self._get_client()

        if self._detected_format == "openai_chat":
            self._messages.append({"role": "user", "content": prompt})
            payload = {"messages": list(self._messages)}
        else:
            payload = {"prompt": prompt}

        start = time.monotonic()
        resp = await client.post(self.url, json=payload)
        latency_ms = round((time.monotonic() - start) * 1000, 1)

        raw_body = resp.text
        headers = dict(resp.headers)

        # Guardrail/transport block detection runs on the raw response — many
        # guardrails return HTTP 200 with a replaced body, so we inspect status,
        # headers, and body together rather than trusting the status code.
        blocked_by = detect_block(resp.status_code, headers, raw_body)

        if raise_for_status:
            resp.raise_for_status()

        content_type = resp.headers.get("content-type", "")
        text = raw_body
        if "application/json" in content_type or "json" in content_type:
            try:
                text = _extract_text(resp.json())
                if self._detected_format == "openai_chat":
                    self._messages.append({"role": "assistant", "content": text})
            except Exception:
                text = raw_body

        return ResponseSignals(
            text=text,
            status_code=resp.status_code,
            latency_ms=latency_ms,
            headers=headers,
            blocked_by=blocked_by,
        )

    async def clone(self) -> HTTPTarget:
        """Create an independent copy with its own messages and client."""
        copy = HTTPTarget(self.url, timeout=self.timeout, headers=dict(self.headers))
        copy._detected_format = self._detected_format
        return copy

    async def reset_conversation(self) -> None:
        """Clear conversation history between strategies."""
        self._messages.clear()

    async def close(self) -> None:
        if self._client and not self._client.is_closed:
            await self._client.aclose()
            self._client = None
