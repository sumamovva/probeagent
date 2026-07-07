"""Tests for the single-source attack registry."""

import pytest

from probeagent.attacks import ATTACK_REGISTRY, get_attack_classes
from probeagent.attacks.base import BaseAttack, register
from probeagent.core.engine import _ATTACK_CLASSES
from probeagent.core.models import Severity


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
