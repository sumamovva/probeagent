"""OpenClaw target adapter — stub for Phase 3."""

from __future__ import annotations

from probeagent.core.models import TargetInfo
from probeagent.targets.base import Target


class OpenClawTarget(Target):
    """Target adapter for OpenClaw agents. Coming in Phase 3."""

    def __init__(self, url: str, **kwargs):
        self.url = url

    async def send(self, prompt: str) -> str:
        raise NotImplementedError("OpenClaw target support is coming in Phase 3.")

    async def validate(self) -> TargetInfo:
        raise NotImplementedError("OpenClaw target support is coming in Phase 3.")
