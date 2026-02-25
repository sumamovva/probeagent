"""MCP (Model Context Protocol) target adapter — stub for Phase 3."""

from __future__ import annotations

from probeagent.core.models import TargetInfo
from probeagent.targets.base import Target


class MCPTarget(Target):
    """Target adapter for MCP servers. Coming in Phase 3."""

    def __init__(self, url: str, **kwargs):
        self.url = url

    async def send(self, prompt: str) -> str:
        raise NotImplementedError("MCP target support is coming in Phase 3.")

    async def validate(self) -> TargetInfo:
        raise NotImplementedError("MCP target support is coming in Phase 3.")
