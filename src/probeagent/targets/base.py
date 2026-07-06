# Copyright 2025 Suma Movva
# SPDX-License-Identifier: Apache-2.0

"""Abstract base class for all targets."""

from __future__ import annotations

from abc import ABC, abstractmethod

from probeagent.core.models import ResponseSignals, TargetInfo


class Target(ABC):
    """Base class for attack targets."""

    @abstractmethod
    async def send(self, prompt: str) -> str:
        """Send a prompt to the target and return its response."""

    async def send_with_signals(self, prompt: str) -> ResponseSignals:
        """Send a prompt and return structured signals (status, latency, body).

        The default wraps :meth:`send` and captures only the text — it cannot
        observe transport/guardrail signals, so ``blocked_by`` stays ``None``
        and such responses classify as Resisted. Transport-aware targets (e.g.
        HTTP) override this to populate status/headers and run guardrail
        detection so genuine Blocked results become observable.
        """
        text = await self.send(prompt)
        return ResponseSignals(text=text)

    @abstractmethod
    async def validate(self) -> TargetInfo:
        """Check reachability and detect the target's API format."""

    async def reset_conversation(self) -> None:
        """Clear conversation state between strategies. Override if needed."""

    async def clone(self) -> Target:
        """Create an independent copy for concurrent strategy execution."""
        raise NotImplementedError

    async def close(self) -> None:
        """Clean up resources. Override if needed."""
