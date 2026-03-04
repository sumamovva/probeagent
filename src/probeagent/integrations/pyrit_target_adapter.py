"""PyRIT target adapter — wraps a ProbeAgent Target so PyRIT orchestrators can attack it.

Usage (requires PyRIT installed):

    from probeagent.targets.http_target import HTTPTarget
    from probeagent.integrations.pyrit_target_adapter import ProbeAgentAsPyRITTarget

    pa_target = HTTPTarget("http://localhost:8000/api/chat")
    pyrit_target = ProbeAgentAsPyRITTarget(pa_target)
    # Now pass pyrit_target to any PyRIT orchestrator
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from probeagent.targets.base import Target

try:
    from pyrit.models import PromptRequestResponse, PromptRequestPiece
    from pyrit.prompt_target import PromptTarget

    _PYRIT_AVAILABLE = True
except ImportError:
    _PYRIT_AVAILABLE = False

if TYPE_CHECKING or _PYRIT_AVAILABLE:

    if _PYRIT_AVAILABLE:

        class ProbeAgentAsPyRITTarget(PromptTarget):
            """Wraps a ProbeAgent Target so PyRIT orchestrators can send prompts to it."""

            def __init__(self, inner: Target) -> None:
                super().__init__()
                self._inner = inner

            async def send_prompt_async(
                self, *, prompt_request: PromptRequestResponse
            ) -> PromptRequestResponse:
                """Send the prompt through the ProbeAgent target and return a response."""
                request_pieces = prompt_request.request_pieces
                if not request_pieces:
                    raise ValueError("Empty prompt request")

                prompt_text = request_pieces[0].original_value
                response_text = await self._inner.send(prompt_text)

                response_piece = PromptRequestPiece(
                    role="assistant",
                    original_value=response_text,
                    converted_value=response_text,
                    original_value_data_type="text",
                    converted_value_data_type="text",
                    prompt_target_identifier=self.get_identifier(),
                )
                return PromptRequestResponse(request_pieces=[response_piece])

            def get_identifier(self) -> dict:
                return {
                    "__type__": "ProbeAgentAsPyRITTarget",
                    "inner": str(type(self._inner).__name__),
                }


def is_adapter_available() -> bool:
    """Return True if the PyRIT target adapter class is usable."""
    return _PYRIT_AVAILABLE
