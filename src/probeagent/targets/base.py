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

    async def close(self) -> None:
        """Clean up resources. Override if needed."""
