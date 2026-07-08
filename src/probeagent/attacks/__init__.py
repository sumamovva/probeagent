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
    from probeagent.core.frameworks import is_valid_atlas, is_valid_code

    registry: dict[str, dict] = {}
    for name, cls in get_attack_classes().items():
        tags = tuple(cls.framework_tags)
        atlas = tuple(cls.atlas_tags)
        # Fail fast on a typo'd taxonomy code — a wrong code on a security tool is
        # worse than none. OWASP and MITRE ATLAS codes are validated separately.
        bad = [c for c in tags if not is_valid_code(c)]
        bad += [c for c in atlas if not is_valid_atlas(c)]
        if bad:
            raise ValueError(f"{cls.__name__} has unknown framework code(s): {bad}")
        registry[name] = {
            "display_name": cls.display_name,
            "severity": cls.severity,
            "description": cls.description,
            "framework_tags": tags,
            "atlas_tags": atlas,
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
