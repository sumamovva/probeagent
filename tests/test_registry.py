"""Tests for the single-source attack registry."""

import pytest

from probeagent.attacks import ATTACK_REGISTRY, get_attack_classes
from probeagent.attacks.base import BaseAttack, register
from probeagent.core.engine import _ATTACK_CLASSES
from probeagent.core.frameworks import (
    ATLAS_TITLES,
    FRAMEWORK_TITLES,
    is_valid_atlas,
    is_valid_code,
)
from probeagent.core.models import Severity

# Approved OWASP mapping (verified against the official OWASP sources).
# ASI = Top 10 for Agentic Applications 2026; LLM = Top 10 for LLM Applications 2025.
EXPECTED_FRAMEWORK_TAGS = {
    "prompt_injection": ("ASI01:2026", "LLM01:2025"),
    "indirect_injection": ("ASI01:2026", "LLM01:2025"),
    "goal_hijacking": ("ASI01:2026",),
    "tool_misuse": ("ASI02:2026", "LLM06:2025"),
    "identity_spoofing": ("ASI03:2026",),
    "credential_exfil": ("ASI03:2026", "LLM02:2025"),
    "agentic_exploitation": ("ASI05:2026", "ASI04:2026", "LLM05:2025"),
    "config_manipulation": ("ASI10:2026", "ASI06:2026", "LLM06:2025"),
    "resource_abuse": ("LLM10:2025",),
    "data_exfil": ("LLM07:2025",),
    "social_manipulation": ("LLM01:2025",),
    "cognitive_exploitation": ("LLM01:2025",),
}


class TestFrameworkTags:
    @pytest.mark.parametrize("name,expected", EXPECTED_FRAMEWORK_TAGS.items())
    def test_attack_has_expected_codes(self, name, expected):
        assert ATTACK_REGISTRY[name]["framework_tags"] == expected

    def test_every_code_is_canonical(self):
        for info in ATTACK_REGISTRY.values():
            for code in info["framework_tags"]:
                assert is_valid_code(code), f"unknown OWASP code {code!r}"

    def test_no_bare_codes_all_versioned(self):
        # Every code carries its edition year (e.g. ASI01:2026, LLM01:2025).
        for info in ATTACK_REGISTRY.values():
            for code in info["framework_tags"]:
                assert ":" in code and code.rsplit(":", 1)[1].isdigit()

    def test_canonical_titles_present(self):
        # Sanity-check a couple of transcribed titles against the map.
        assert FRAMEWORK_TITLES["ASI01:2026"] == "Agent Goal Hijack"
        assert FRAMEWORK_TITLES["LLM10:2025"] == "Unbounded Consumption"


# MITRE ATLAS technique IDs verified against github.com/mitre-atlas/atlas-data.
EXPECTED_ATLAS_TAGS = {
    "prompt_injection": ("AML.T0051", "AML.T0054"),
    "indirect_injection": ("AML.T0051.001", "AML.T0070"),
    "goal_hijacking": ("AML.T0051",),
    "tool_misuse": ("AML.T0053", "AML.T0050"),
    "identity_spoofing": ("AML.T0073",),
    "credential_exfil": ("AML.T0057", "AML.T0055"),
    "agentic_exploitation": ("AML.T0050", "AML.T0011"),
    "config_manipulation": ("AML.T0053", "AML.T0050"),
    "resource_abuse": ("AML.T0034.002", "AML.T0029"),
    "data_exfil": ("AML.T0056", "AML.T0057"),
    "social_manipulation": ("AML.T0054",),
    "cognitive_exploitation": ("AML.T0054",),
}


class TestAtlasTags:
    @pytest.mark.parametrize("name,expected", EXPECTED_ATLAS_TAGS.items())
    def test_attack_has_expected_atlas(self, name, expected):
        assert ATTACK_REGISTRY[name]["atlas_tags"] == expected

    def test_every_atlas_code_is_canonical(self):
        for info in ATTACK_REGISTRY.values():
            for code in info["atlas_tags"]:
                assert is_valid_atlas(code), f"unknown ATLAS id {code!r}"

    def test_atlas_ids_well_formed(self):
        for info in ATTACK_REGISTRY.values():
            for code in info["atlas_tags"]:
                assert code.startswith("AML.T")

    def test_atlas_titles_present(self):
        assert ATLAS_TITLES["AML.T0051.001"] == "LLM Prompt Injection: Indirect"
        assert ATLAS_TITLES["AML.T0053"] == "AI Agent Tool Invocation"


def test_all_attacks_discovered():
    # Auto-discovery picks up every attack module (currently 12).
    assert len(ATTACK_REGISTRY) >= 12


def test_engine_and_metadata_share_one_source():
    # The engine's class map and the metadata registry are the same set of names.
    assert set(_ATTACK_CLASSES) == set(ATTACK_REGISTRY)
    assert set(get_attack_classes()) == set(ATTACK_REGISTRY)


def test_metadata_derived_from_class_no_drift():
    # Registry metadata is read straight off the class — it cannot drift.
    for name, cls in get_attack_classes().items():
        info = ATTACK_REGISTRY[name]
        assert info["display_name"] == cls.display_name
        assert info["severity"] == cls.severity
        assert info["description"] == cls.description
        assert info["class"] == cls.__name__


def test_every_registered_class_is_a_baseattack():
    for cls in get_attack_classes().values():
        assert issubclass(cls, BaseAttack)


def test_register_requires_name():
    with pytest.raises(ValueError):

        @register
        class _NoName(BaseAttack):
            display_name = "x"
            severity = Severity.LOW
            description = "x"


def test_register_rejects_duplicate_name():
    with pytest.raises(ValueError):

        @register
        class _Dup(BaseAttack):
            name = "prompt_injection"  # already taken
            display_name = "x"
            severity = Severity.LOW
            description = "x"
