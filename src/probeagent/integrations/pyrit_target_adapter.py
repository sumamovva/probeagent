# Copyright 2025 Suma Movva
# SPDX-License-Identifier: Apache-2.0

"""Adapter exposing a ProbeAgent Target as a PyRIT ``PromptChatTarget``.

Lets PyRIT's attack strategies (e.g. ``RedTeamingAttack``) drive any ProbeAgent
target. Built against the PyRIT 0.14 API; guarded so the rest of ProbeAgent works
without PyRIT installed.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from probeagent.targets.base import Target

try:
    from pyrit.models import Message, MessagePiece
    from pyrit.prompt_target import PromptChatTarget

    _HAS_PYRIT = True
except ImportError:  # pragma: no cover - exercised only without the extra
    _HAS_PYRIT = False


def is_adapter_available() -> bool:
    """True when PyRIT is importable and the adapter can be used."""
    return _HAS_PYRIT


if _HAS_PYRIT:

    class ProbeAgentAsPyRITTarget(PromptChatTarget):
        """Wraps a ProbeAgent ``Target`` so PyRIT can send prompts to it.

        PyRIT owns the conversation; each turn we forward the latest attacker
        message to the ProbeAgent target and return its reply as a PyRIT ``Message``.
        """

        def __init__(self, target: "Target") -> None:
            super().__init__()
            self._target = target
            # (attacker_prompt, agent_reply) pairs, for building a transcript afterwards.
            self.turns: list[tuple[str, str]] = []

        async def _send_prompt_to_target_async(
            self, *, normalized_conversation: list["Message"]
        ) -> list["Message"]:
            prompt = normalized_conversation[-1].get_value()
            reply = await self._target.send(prompt)
            self.turns.append((prompt, reply or ""))
            return [
                Message(
                    message_pieces=[
                        MessagePiece(
                            role="assistant",
                            original_value=reply or "",
                            original_value_data_type="text",
                        )
                    ]
                )
            ]

        def _validate_request(self, **kwargs: object) -> None:  # noqa: D401
            """No provider-specific constraints on a ProbeAgent target."""

        def is_json_response_supported(self) -> bool:
            return False
