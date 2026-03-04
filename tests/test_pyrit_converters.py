"""Tests for PyRIT converter pipeline."""

from __future__ import annotations

import pytest

from probeagent.integrations.pyrit_converters import (
    CONVERTER_PRESETS,
    get_available_converters,
    is_pyrit_available,
    parse_converter_arg,
)


class TestPyRITConverters:
    def test_is_pyrit_available_returns_bool(self):
        result = is_pyrit_available()
        assert isinstance(result, bool)

    def test_converter_presets_defined(self):
        assert "basic" in CONVERTER_PRESETS
        assert "advanced" in CONVERTER_PRESETS
        assert "stealth" in CONVERTER_PRESETS
        for preset_name, converters in CONVERTER_PRESETS.items():
            assert isinstance(converters, list)
            assert len(converters) > 0

    def test_get_available_converters(self):
        converters = get_available_converters()
        assert isinstance(converters, list)
        assert len(converters) > 0
        assert "base64" in converters
        assert "rot13" in converters

    def test_parse_converter_arg_preset(self):
        result = parse_converter_arg("basic")
        assert result == CONVERTER_PRESETS["basic"]

    def test_parse_converter_arg_comma_separated(self):
        result = parse_converter_arg("base64,rot13")
        assert result == ["base64", "rot13"]

    def test_parse_converter_arg_with_spaces(self):
        result = parse_converter_arg("  base64 , rot13 ")
        assert result == ["base64", "rot13"]

    @pytest.mark.asyncio
    async def test_apply_converters_without_pyrit_raises(self):
        if is_pyrit_available():
            pytest.skip("PyRIT is installed — cannot test import error path")
        from probeagent.integrations.pyrit_converters import apply_converters

        with pytest.raises(ImportError, match="PyRIT is required"):
            await apply_converters("test prompt", ["base64"])
