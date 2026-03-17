# Copyright 2025 Suma Movva
# SPDX-License-Identifier: Apache-2.0

"""Converting target proxy — wraps any Target, applies PyRIT converters to prompts.

This is the zero-modification approach: no existing attack class needs to change.
The engine wraps the target when converters are configured.
"""

from __future__ import annotations

from probeagent.core.models import TargetInfo
from probeagent.targets.base import Target


class ConvertingTargetProxy(Target):
    """Proxy that applies PyRIT converter transformations before sending prompts."""

    def __init__(self, inner: Target, converters: list[str]) -> None:
        self._inner = inner
        self._converters = converters

    async def send(self, prompt: str) -> str:
        """Apply converters to the prompt, then delegate to the inner target."""
        from probeagent.integrations.pyrit_converters import apply_converters

        converted = await apply_converters(prompt, self._converters)
        return await self._inner.send(converted)

    async def validate(self) -> TargetInfo:
        """Delegate validation to the inner target."""
        return await self._inner.validate()

    async def reset_conversation(self) -> None:
        """Delegate reset to the inner target."""
        await self._inner.reset_conversation()

    async def clone(self) -> ConvertingTargetProxy:
        """Clone the inner target and wrap with the same converters."""
        cloned_inner = await self._inner.clone()
        return ConvertingTargetProxy(cloned_inner, list(self._converters))

    async def close(self) -> None:
        """Delegate close to the inner target."""
        await self._inner.close()
