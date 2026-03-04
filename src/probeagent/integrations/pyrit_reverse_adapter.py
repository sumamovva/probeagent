"""PyRIT reverse adapter — wraps a PyRIT PromptTarget so it works with ProbeAgent's engine.

This enables `probeagent attack` against any PyRIT-supported endpoint.

Usage (requires PyRIT installed):

    from pyrit.prompt_target import AzureOpenAITarget
    from probeagent.integrations.pyrit_reverse_adapter import PyRITAsProbeAgentTarget

    pyrit_target = AzureOpenAITarget(deployment_name="gpt-4", ...)
    pa_target = PyRITAsProbeAgentTarget(pyrit_target)
    # Now use pa_target with AttackEngine
"""

from __future__ import annotations

from typing import Any

from probeagent.core.models import TargetInfo
from probeagent.targets.base import Target

try:
    from pyrit.models import PromptRequestPiece, PromptRequestResponse

    _PYRIT_AVAILABLE = True
except ImportError:
    _PYRIT_AVAILABLE = False


class PyRITAsProbeAgentTarget(Target):
    """Wraps a PyRIT PromptTarget for use with ProbeAgent's AttackEngine."""

    def __init__(self, pyrit_target: Any) -> None:
        if not _PYRIT_AVAILABLE:
            raise ImportError(
                "PyRIT is required for the reverse adapter. "
                "Install with: pip install 'probeagent[pyrit]'"
            )
        self._pyrit_target = pyrit_target

    async def send(self, prompt: str) -> str:
        """Send a prompt through the PyRIT target and return the response text."""
        request_piece = PromptRequestPiece(
            role="user",
            original_value=prompt,
            converted_value=prompt,
            original_value_data_type="text",
            converted_value_data_type="text",
        )
        request = PromptRequestResponse(request_pieces=[request_piece])
        response = await self._pyrit_target.send_prompt_async(prompt_request=request)

        if response.request_pieces:
            return response.request_pieces[0].converted_value or ""
        return ""

    async def validate(self) -> TargetInfo:
        """Validate connectivity — PyRIT targets don't have a standard validation method."""
        return TargetInfo(
            url=f"pyrit://{type(self._pyrit_target).__name__}",
            reachable=True,
            detected_format="pyrit",
        )

    async def close(self) -> None:
        """Clean up — call dispose if available on the PyRIT target."""
        if hasattr(self._pyrit_target, "dispose"):
            self._pyrit_target.dispose()


def is_reverse_adapter_available() -> bool:
    """Return True if PyRIT is available for the reverse adapter."""
    return _PYRIT_AVAILABLE
