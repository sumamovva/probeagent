# Copyright 2025 Suma Movva
# SPDX-License-Identifier: Apache-2.0

"""PyRIT converter pipeline — evasion transformations on attack prompts.

Wraps PyRIT converters behind a conditional import so the rest of ProbeAgent
works without PyRIT installed.
"""

from __future__ import annotations

import asyncio
from typing import Any


def is_pyrit_available() -> bool:
    """Return True if PyRIT is importable."""
    try:
        import pyrit  # noqa: F401

        return True
    except ImportError:
        return False


# ── Converter short-name → PyRIT class mapping ──

_CONVERTER_MAP: dict[str, str] = {
    "base64": "Base64Converter",
    "rot13": "ROT13Converter",
    "unicode_confusable": "UnicodeConfusableConverter",
    "unicode_substitution": "UnicodeSubstitutionConverter",
    "leetspeak": "LeetspeakConverter",
    "atbash": "AtbashConverter",
    "caesar": "CaesarConverter",
    "morse": "MorseConverter",
    "binary": "BinaryConverter",
    "flip": "FlipConverter",
    "reverse": "StringReverseConverter",
}

# ── Presets: curated chains for common use-cases ──

CONVERTER_PRESETS: dict[str, list[str]] = {
    "basic": ["base64"],
    "advanced": ["leetspeak", "base64"],
    "stealth": ["unicode_confusable", "leetspeak"],
}


def get_available_converters() -> list[str]:
    """Return all known converter short names."""
    return list(_CONVERTER_MAP.keys())


def _resolve_converters(converter_names: list[str]) -> list[Any]:
    """Resolve short names to PyRIT converter instances.

    Raises ImportError if PyRIT is not installed.
    """
    try:
        import pyrit.prompt_converter as pc
    except ImportError:
        raise ImportError(
            "PyRIT is required for converter support. Install with: pip install 'probeagent[pyrit]'"
        )

    instances = []
    for name in converter_names:
        cls_name = _CONVERTER_MAP.get(name)
        if cls_name is None:
            raise ValueError(f"Unknown converter '{name}'. Available: {', '.join(_CONVERTER_MAP)}")
        cls = getattr(pc, cls_name, None)
        if cls is None:
            raise ValueError(
                f"PyRIT converter class '{cls_name}' not found. "
                f"Your PyRIT version may not support it."
            )
        instances.append(cls())
    return instances


async def apply_converters(prompt: str, converter_names: list[str]) -> str:
    """Apply a chain of PyRIT converters to a prompt string.

    Each converter transforms the output of the previous one.
    Returns the final converted string.

    Raises ImportError if PyRIT is not installed.
    """
    converters = _resolve_converters(converter_names)
    result = prompt
    for converter in converters:
        if asyncio.iscoroutinefunction(getattr(converter, "convert_async", None)):
            converted = await converter.convert_async(prompt=result)
        else:
            converted = converter.convert(prompt=result)
        # PyRIT converters return ConverterResult with .output_text
        if hasattr(converted, "output_text"):
            result = converted.output_text
        elif isinstance(converted, str):
            result = converted
        else:
            result = str(converted)
    return result


def parse_converter_arg(value: str) -> list[str]:
    """Parse a CLI converter argument into a list of converter names.

    Accepts either a preset name (e.g. "basic") or comma-separated names.
    """
    value = value.strip()
    if value in CONVERTER_PRESETS:
        return CONVERTER_PRESETS[value]
    return [c.strip() for c in value.split(",") if c.strip()]
