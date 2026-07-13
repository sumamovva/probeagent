# Copyright 2025 Suma Movva
# SPDX-License-Identifier: Apache-2.0

"""Evasion converters — obfuscation transforms applied to attack prompts.

Pure-Python, no external dependency: each converter rewrites a prompt into an
obfuscated form (encoded, substituted, reversed) to test whether a target's
defenses can be bypassed by a differently-shaped payload. Chain them with
``--converters`` (a preset or a comma-separated list).
"""

from __future__ import annotations

import base64 as _b64
import codecs

# ── Individual transforms (str -> str) ──

_LEET = str.maketrans({"a": "4", "e": "3", "i": "1", "o": "0", "s": "5", "t": "7", "l": "1"})
# Latin -> visually-confusable Cyrillic/Greek homoglyphs.
_CONFUSABLE = str.maketrans(
    {
        "a": "а",
        "c": "с",
        "e": "е",
        "i": "і",
        "j": "ј",
        "o": "о",
        "p": "р",
        "s": "ѕ",
        "x": "х",
        "y": "у",
    }
)
# Latin -> fullwidth forms (visually similar, different code points).
_FULLWIDTH = {chr(c): chr(c - 0x20 + 0xFF00) for c in range(0x21, 0x7F)}
_FLIP = str.maketrans("abcdefghijklmnopqrstuvwxyz", "ɐqɔpǝɟƃɥᴉɾʞlɯuodbɹsʇnʌʍxʎz")
_MORSE = {
    "a": ".-",
    "b": "-...",
    "c": "-.-.",
    "d": "-..",
    "e": ".",
    "f": "..-.",
    "g": "--.",
    "h": "....",
    "i": "..",
    "j": ".---",
    "k": "-.-",
    "l": ".-..",
    "m": "--",
    "n": "-.",
    "o": "---",
    "p": ".--.",
    "q": "--.-",
    "r": ".-.",
    "s": "...",
    "t": "-",
    "u": "..-",
    "v": "...-",
    "w": ".--",
    "x": "-..-",
    "y": "-.--",
    "z": "--..",
    "0": "-----",
    "1": ".----",
    "2": "..---",
    "3": "...--",
    "4": "....-",
    "5": ".....",
    "6": "-....",
    "7": "--...",
    "8": "---..",
    "9": "----.",
    " ": "/",
}


def _base64(s: str) -> str:
    return _b64.b64encode(s.encode("utf-8")).decode("ascii")


def _rot13(s: str) -> str:
    return codecs.encode(s, "rot_13")


def _leetspeak(s: str) -> str:
    return s.translate(_LEET)


def _unicode_confusable(s: str) -> str:
    return s.translate(_CONFUSABLE)


def _unicode_substitution(s: str) -> str:
    return "".join(_FULLWIDTH.get(ch, ch) for ch in s)


def _atbash(s: str) -> str:
    def flip(ch: str) -> str:
        if "a" <= ch <= "z":
            return chr(ord("z") - (ord(ch) - ord("a")))
        if "A" <= ch <= "Z":
            return chr(ord("Z") - (ord(ch) - ord("A")))
        return ch

    return "".join(flip(c) for c in s)


def _caesar(s: str, shift: int = 3) -> str:
    def sh(ch: str) -> str:
        if "a" <= ch <= "z":
            return chr((ord(ch) - ord("a") + shift) % 26 + ord("a"))
        if "A" <= ch <= "Z":
            return chr((ord(ch) - ord("A") + shift) % 26 + ord("A"))
        return ch

    return "".join(sh(c) for c in s)


def _morse(s: str) -> str:
    return " ".join(_MORSE.get(c, c) for c in s.lower())


def _binary(s: str) -> str:
    return " ".join(format(b, "08b") for b in s.encode("utf-8"))


def _flip(s: str) -> str:
    return s.lower().translate(_FLIP)[::-1]


def _reverse(s: str) -> str:
    return s[::-1]


_CONVERTERS = {
    "base64": _base64,
    "rot13": _rot13,
    "leetspeak": _leetspeak,
    "unicode_confusable": _unicode_confusable,
    "unicode_substitution": _unicode_substitution,
    "atbash": _atbash,
    "caesar": _caesar,
    "morse": _morse,
    "binary": _binary,
    "flip": _flip,
    "reverse": _reverse,
}

# ── Presets: curated chains for common use-cases ──

CONVERTER_PRESETS: dict[str, list[str]] = {
    "basic": ["base64"],
    "advanced": ["leetspeak", "base64"],
    "stealth": ["unicode_confusable", "leetspeak"],
}


def get_available_converters() -> list[str]:
    """Return all known converter short names."""
    return list(_CONVERTERS.keys())


async def apply_converters(prompt: str, converter_names: list[str]) -> str:
    """Apply a chain of converters to a prompt; each transforms the previous output.

    Async for API symmetry with the attack pipeline; the transforms themselves are sync.
    """
    result = prompt
    for name in converter_names:
        fn = _CONVERTERS.get(name)
        if fn is None:
            raise ValueError(f"Unknown converter '{name}'. Available: {', '.join(_CONVERTERS)}")
        result = fn(result)
    return result


def parse_converter_arg(value: str) -> list[str]:
    """Parse a CLI converter argument: a preset name (e.g. 'basic') or comma-separated names."""
    value = value.strip()
    if value in CONVERTER_PRESETS:
        return CONVERTER_PRESETS[value]
    return [c.strip() for c in value.split(",") if c.strip()]
