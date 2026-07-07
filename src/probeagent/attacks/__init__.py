# Copyright 2025 Suma Movva
# SPDX-License-Identifier: Apache-2.0

"""Attack registry — derived from the registered attack classes.

There is a single source of truth: each attack class declares its own metadata
and applies ``@register`` (see ``base.py``). Importing this package imports every
attack module, which registers it. ``ATTACK_REGISTRY`` and the engine both read
from that registry, so class and metadata can never drift.
"""

from __future__ import annotations

import importlib
import pkgutil

from probeagent.attacks.base import BaseAttack, get_attack_classes, register


def _discover_attacks() -> None:
    """Import every attack submodule so its ``@register`` decorator runs.

    Auto-discovery means adding an attack is a single-file change: drop a new
    module in this package with a ``@register`` class and it is picked up — no
    edits to this file or the engine.
    """
    for mod in pkgutil.iter_modules(__path__):
        if mod.name == "base" or mod.name.startswith("_"):
            continue
        importlib.import_module(f"{__name__}.{mod.name}")


_discover_attacks()

__all__ = [
    "ATTACK_REGISTRY",
    "BaseAttack",
    "get_attack_classes",
    "get_attack_info",
    "get_attack_names",
    "register",
]


def _build_registry() -> dict[str, dict]:
    registry: dict[str, dict] = {}
    for name, cls in get_attack_classes().items():
        registry[name] = {
            "display_name": cls.display_name,
            "severity": cls.severity,
            "description": cls.description,
            "framework_tags": tuple(cls.framework_tags),
            "module": cls.__module__,
            "class": cls.__name__,
        }
    return registry


ATTACK_REGISTRY: dict[str, dict] = _build_registry()


def get_attack_names() -> list[str]:
    """Return all registered attack names."""
    return list(ATTACK_REGISTRY.keys())


def get_attack_info(name: str) -> dict | None:
    """Return metadata for a specific attack, or None if not found."""
    return ATTACK_REGISTRY.get(name)
