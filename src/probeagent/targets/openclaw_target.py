# Copyright 2025 Suma Movva
# SPDX-License-Identifier: Apache-2.0

"""OpenClaw target adapter — connects to an OpenClaw agent via its WebChat HTTP API."""

from __future__ import annotations

import time
from uuid import uuid4

import httpx

from probeagent.core.models import TargetInfo
from probeagent.targets.base import Target


class OpenClawTarget(Target):
    """Target adapter for OpenClaw AI agents.

    Connects via the WebChat HTTP endpoint that OpenClaw exposes.
    Default: http://127.0.0.1:5678/webhook/webchat (n8n-style) or
    configurable URL.

    OpenClaw agents typically respond with JSON:
        {"response": "...", "sessionId": "..."}
    """

    def __init__(
        self,
        url: str,
        *,
        timeout: float = 30.0,
        session_id: str | None = None,
        headers: dict | None = None,
    ):
        self.url = url
        self.timeout = timeout
        self.session_id = session_id or "probeagent-session"
        self.headers = headers or {}
        self._client: httpx.AsyncClient | None = None

    def _get_client(self) -> httpx.AsyncClient:
        if self._client is None or self._client.is_closed:
            self._client = httpx.AsyncClient(
                timeout=self.timeout,
                headers=self.headers,
                follow_redirects=True,
            )
        return self._client

    async def validate(self) -> TargetInfo:
        """Probe the OpenClaw agent to check reachability."""
        client = self._get_client()
        start = time.monotonic()
        try:
            resp = await client.post(
                self.url,
                json={
                    "action": "sendMessage",
                    "chatInput": "ping",
                    "sessionId": self.session_id,
                },
            )
            elapsed_ms = (time.monotonic() - start) * 1000

            return TargetInfo(
                url=self.url,
                reachable=True,
                response_time_ms=round(elapsed_ms, 1),
                detected_format="openclaw",
                status_code=resp.status_code,
            )
        except httpx.TimeoutException:
            return TargetInfo(url=self.url, reachable=False, error="Connection timed out")
        except httpx.ConnectError as exc:
            return TargetInfo(url=self.url, reachable=False, error=f"Connection failed: {exc}")
        except Exception as exc:
            return TargetInfo(url=self.url, reachable=False, error=str(exc))

    async def send(self, prompt: str) -> str:
        """Send a prompt to the OpenClaw agent and return its response."""
        client = self._get_client()
        resp = await client.post(
            self.url,
            json={
                "action": "sendMessage",
                "chatInput": prompt,
                "sessionId": self.session_id,
            },
        )
        resp.raise_for_status()

        content_type = resp.headers.get("content-type", "")
        if "application/json" in content_type or "json" in content_type:
            try:
                data = resp.json()
                return self._extract_response(data)
            except Exception:
                pass

        return resp.text

    @staticmethod
    def _extract_response(data: dict | list | str) -> str:
        """Extract the agent's response text from OpenClaw's JSON format."""
        if isinstance(data, str):
            return data

        if isinstance(data, list) and data:
            # Some OpenClaw setups return a list of message objects
            last = data[-1]
            if isinstance(last, dict):
                for key in ("output", "response", "text", "content", "message"):
                    if key in last:
                        return str(last[key])
            return str(last)

        if isinstance(data, dict):
            # Standard OpenClaw response keys
            for key in ("output", "response", "text", "content", "message", "result"):
                if key in data:
                    val = data[key]
                    if isinstance(val, str):
                        return val
                    if isinstance(val, dict) and "content" in val:
                        return str(val["content"])

        return str(data)

    async def clone(self) -> OpenClawTarget:
        """Create an independent copy with a fresh session ID."""
        return OpenClawTarget(
            self.url,
            timeout=self.timeout,
            session_id=f"probeagent-session-{uuid4().hex[:8]}",
            headers=dict(self.headers),
        )

    async def reset_conversation(self) -> None:
        """Reset the session ID to start a fresh conversation."""
        self.session_id = f"probeagent-session-{uuid4().hex[:8]}"

    async def close(self) -> None:
        if self._client and not self._client.is_closed:
            await self._client.aclose()
            self._client = None
