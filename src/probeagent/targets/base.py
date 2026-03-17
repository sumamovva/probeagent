# Copyright 2025 Suma Movva
# SPDX-License-Identifier: Apache-2.0

"""Abstract base class for all targets."""

from __future__ import annotations

from abc import ABC, abstractmethod

from probeagent.core.models import TargetInfo


class Target(ABC):
    """Base class for attack targets."""

    @abstractmethod
    async def send(self, prompt: str) -> str:
        """Send a prompt to the target and return its response."""

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
