# Copyright 2025 Suma Movva
# SPDX-License-Identifier: Apache-2.0

"""MCP (Model Context Protocol) target adapter.

Speaks MCP JSON-RPC 2.0 over the Streamable HTTP transport using ``httpx`` — no
MCP SDK dependency. It performs the ``initialize`` handshake, enumerates the
server's tools (``tools/list``), and exposes two offensive surfaces:

- **Tool-poisoning detection** (dynamic, at :meth:`validate`): tool descriptions
  and parameter docs are fetched live and scanned for hidden-instruction
  signatures — the primary MCP attack class (OWASP MCP03). Findings surface in
  the reported ``detected_format`` so a run flags them without a static config scan.
- **Tool invocation** (:meth:`send`): a prompt is passed as the argument to the
  server's first string-accepting tool via ``tools/call``, and the textual result
  is returned — letting the existing prompt-based attack modules exercise the
  tool-use loop.

Limitations (honest scope): only the Streamable HTTP transport is supported
(remote servers), not stdio. ``send`` targets one heuristically-chosen tool; it
does not plan multi-tool call chains.
"""

from __future__ import annotations

import json
import time

import httpx

from probeagent.core.guardrails import detect_block
from probeagent.core.models import ResponseSignals, TargetInfo
from probeagent.targets.base import Target

_PROTOCOL_VERSION = "2025-06-18"

# Hidden-instruction signatures that, in a tool description, indicate poisoning.
_POISON_SIGNATURES = (
    "ignore previous",
    "ignore all previous",
    "ignore the above",
    "disregard previous",
    "<important>",
    "<system>",
    "do not tell",
    "do not mention",
    "without informing",
    "system:",
    "assistant:",
    "new instructions",
    "you must",
)


def _text_from_result(result: dict) -> str:
    """Extract concatenated text from an MCP result's content array."""
    if not isinstance(result, dict):
        return str(result)
    content = result.get("content")
    if isinstance(content, list):
        parts = [
            c.get("text", "") for c in content if isinstance(c, dict) and c.get("type") == "text"
        ]
        if parts:
            return "\n".join(p for p in parts if p)
    # tools/list and other results: fall back to a compact JSON dump.
    return json.dumps(result)


class MCPTarget(Target):
    """Target that attacks an MCP server over Streamable HTTP."""

    def __init__(
        self,
        url: str,
        *,
        timeout: float = 30.0,
        headers: dict | None = None,
    ):
        self.url = url
        self.timeout = timeout
        self.headers = headers or {}
        self._client: httpx.AsyncClient | None = None
        self._session_id: str | None = None
        self._next_id = 0
        self._tools: list[dict] = []

    def _get_client(self) -> httpx.AsyncClient:
        if self._client is None or self._client.is_closed:
            base = {
                "Accept": "application/json, text/event-stream",
                "Content-Type": "application/json",
                **self.headers,
            }
            self._client = httpx.AsyncClient(timeout=self.timeout, headers=base)
        return self._client

    def _rpc_id(self) -> int:
        self._next_id += 1
        return self._next_id

    @staticmethod
    def _parse_response(resp: httpx.Response) -> dict:
        """Return the JSON-RPC payload from a JSON or SSE (text/event-stream) body."""
        content_type = resp.headers.get("content-type", "")
        if "text/event-stream" in content_type:
            # Concatenate all `data:` lines; return the last JSON object seen.
            payload: dict = {}
            for line in resp.text.splitlines():
                line = line.strip()
                if line.startswith("data:"):
                    chunk = line[len("data:") :].strip()
                    if chunk:
                        payload = json.loads(chunk)
            return payload
        return resp.json()

    async def _call(self, method: str, params: dict | None = None) -> dict:
        """Send a JSON-RPC request and return its ``result`` (raises on error)."""
        client = self._get_client()
        body = {"jsonrpc": "2.0", "id": self._rpc_id(), "method": method}
        if params is not None:
            body["params"] = params

        extra = {"Mcp-Session-Id": self._session_id} if self._session_id else {}
        resp = await client.post(self.url, json=body, headers=extra)
        resp.raise_for_status()

        sid = resp.headers.get("mcp-session-id")
        if sid:
            self._session_id = sid

        data = self._parse_response(resp)
        if isinstance(data, dict) and data.get("error"):
            raise RuntimeError(f"MCP error on {method}: {data['error']}")
        return data.get("result", {}) if isinstance(data, dict) else {}

    async def _notify(self, method: str) -> None:
        """Fire a JSON-RPC notification (no id, best-effort)."""
        client = self._get_client()
        extra = {"Mcp-Session-Id": self._session_id} if self._session_id else {}
        try:
            await client.post(self.url, json={"jsonrpc": "2.0", "method": method}, headers=extra)
        except Exception:
            pass

    async def _handshake(self) -> None:
        await self._call(
            "initialize",
            {
                "protocolVersion": _PROTOCOL_VERSION,
                "capabilities": {},
                "clientInfo": {"name": "probeagent", "version": "0.2.3"},
            },
        )
        await self._notify("notifications/initialized")
        result = await self._call("tools/list")
        tools = result.get("tools", [])
        self._tools = tools if isinstance(tools, list) else []

    def poisoned_tools(self) -> list[tuple[str, str]]:
        """Return (tool_name, matched_signature) for tools with poisoned descriptions."""
        findings: list[tuple[str, str]] = []
        for tool in self._tools:
            name = str(tool.get("name", "?"))
            blob = str(tool.get("description", ""))
            schema = tool.get("inputSchema") or {}
            props = schema.get("properties", {}) if isinstance(schema, dict) else {}
            for prop in props.values():
                if isinstance(prop, dict):
                    blob += " " + str(prop.get("description", ""))
            low = blob.lower()
            for sig in _POISON_SIGNATURES:
                if sig in low:
                    findings.append((name, sig))
                    break
        return findings

    def _first_string_tool(self) -> tuple[str, str] | None:
        """Find (tool_name, arg_name) of the first tool taking a string argument."""
        for tool in self._tools:
            schema = tool.get("inputSchema") or {}
            props = schema.get("properties", {}) if isinstance(schema, dict) else {}
            for arg_name, prop in props.items():
                if isinstance(prop, dict) and prop.get("type", "string") == "string":
                    return str(tool.get("name")), str(arg_name)
        return None

    async def validate(self) -> TargetInfo:
        start = time.monotonic()
        try:
            await self._handshake()
            elapsed = (time.monotonic() - start) * 1000
            fmt = f"mcp ({len(self._tools)} tools)"
            poisoned = self.poisoned_tools()
            if poisoned:
                names = ", ".join(sorted({n for n, _ in poisoned}))
                fmt = f"mcp · TOOL POISONING suspected: {names}"
            return TargetInfo(
                url=self.url,
                reachable=True,
                response_time_ms=round(elapsed, 1),
                detected_format=fmt,
            )
        except httpx.TimeoutException:
            return TargetInfo(url=self.url, reachable=False, error="Connection timed out")
        except httpx.ConnectError as exc:
            return TargetInfo(url=self.url, reachable=False, error=f"Connection failed: {exc}")
        except Exception as exc:
            return TargetInfo(url=self.url, reachable=False, error=str(exc))

    async def send(self, prompt: str) -> str:
        signals = await self.send_with_signals(prompt)
        return signals.text

    async def send_with_signals(self, prompt: str) -> ResponseSignals:
        if not self._tools:
            # validate() populates tools; if a caller skipped it, handshake now.
            await self._handshake()

        target_tool = self._first_string_tool()
        if target_tool is None:
            return ResponseSignals(text="", headers={})

        tool_name, arg_name = target_tool
        start = time.monotonic()
        client = self._get_client()
        extra = {"Mcp-Session-Id": self._session_id} if self._session_id else {}
        body = {
            "jsonrpc": "2.0",
            "id": self._rpc_id(),
            "method": "tools/call",
            "params": {"name": tool_name, "arguments": {arg_name: prompt}},
        }
        resp = await client.post(self.url, json=body, headers=extra)
        latency_ms = round((time.monotonic() - start) * 1000, 1)
        raw_body = resp.text
        headers = dict(resp.headers)
        blocked_by = detect_block(resp.status_code, headers, raw_body)

        text = raw_body
        try:
            data = self._parse_response(resp)
            if isinstance(data, dict):
                text = _text_from_result(data.get("result", data))
        except Exception:
            pass

        return ResponseSignals(
            text=text,
            status_code=resp.status_code,
            latency_ms=latency_ms,
            headers=headers,
            blocked_by=blocked_by,
        )

    async def clone(self) -> MCPTarget:
        copy = MCPTarget(self.url, timeout=self.timeout, headers=dict(self.headers))
        copy._tools = list(self._tools)
        copy._session_id = self._session_id
        return copy

    async def close(self) -> None:
        if self._client and not self._client.is_closed:
            await self._client.aclose()
            self._client = None
