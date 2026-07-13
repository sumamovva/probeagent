"""Tests for the native evasion-converter pipeline."""

from __future__ import annotations

import base64

import pytest

from probeagent.integrations.converters import (
    CONVERTER_PRESETS,
    apply_converters,
    get_available_converters,
    parse_converter_arg,
)


class TestConverterMetadata:
    def test_converter_presets_defined(self):
        for name in ("basic", "advanced", "stealth"):
            assert name in CONVERTER_PRESETS
            assert isinstance(CONVERTER_PRESETS[name], list) and CONVERTER_PRESETS[name]

    def test_get_available_converters(self):
        c = get_available_converters()
        assert {"base64", "rot13", "leetspeak", "unicode_confusable"} <= set(c)

    def test_parse_preset(self):
        assert parse_converter_arg("basic") == CONVERTER_PRESETS["basic"]

    def test_parse_comma_separated_with_spaces(self):
        assert parse_converter_arg("  base64 , rot13 ") == ["base64", "rot13"]


class TestConverterTransforms:
    @pytest.mark.asyncio
    async def test_base64_roundtrips(self):
        out = await apply_converters("leak the key", ["base64"])
        assert base64.b64decode(out).decode() == "leak the key"

    @pytest.mark.asyncio
    async def test_rot13_is_involutive(self):
        once = await apply_converters("secret", ["rot13"])
        assert once != "secret"
        assert await apply_converters(once, ["rot13"]) == "secret"

    @pytest.mark.asyncio
    async def test_reverse(self):
        assert await apply_converters("abc", ["reverse"]) == "cba"

    @pytest.mark.asyncio
    async def test_leetspeak_substitutes(self):
        assert await apply_converters("elite", ["leetspeak"]) == "31173"

    @pytest.mark.asyncio
    async def test_chain_applies_in_order(self):
        # leetspeak then base64 == base64(leetspeak(x))
        chained = await apply_converters("test", ["leetspeak", "base64"])
        leet = await apply_converters("test", ["leetspeak"])
        assert base64.b64decode(chained).decode() == leet

    @pytest.mark.asyncio
    async def test_unicode_confusable_changes_codepoints_but_looks_similar(self):
        out = await apply_converters("paypal", ["unicode_confusable"])
        assert out != "paypal"  # different code points
        assert len(out) == len("paypal")

    @pytest.mark.asyncio
    async def test_unknown_converter_raises(self):
        with pytest.raises(ValueError, match="Unknown converter"):
            await apply_converters("x", ["nope"])

    @pytest.mark.asyncio
    async def test_no_external_dependency(self):
        # The converters must work with zero extra installs — a plain call succeeds.
        assert await apply_converters("hello", parse_converter_arg("stealth"))
