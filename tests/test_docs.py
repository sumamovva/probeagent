"""Guard the README's factual claims against registry ground truth so the
documented attack/strategy counts can't silently drift."""

import re
from pathlib import Path

from probeagent.attacks import get_attack_classes

README = Path(__file__).resolve().parent.parent / "README.md"


def _ground_truth() -> tuple[int, int]:
    # The documented headline counts strategy-bearing categories only. Runtime
    # loaders like seed_corpus carry no built-in STRATEGIES (they are populated
    # from --seeds files at runtime), so they are not part of the category count.
    classes = {n: c for n, c in get_attack_classes().items() if c.STRATEGIES}
    return len(classes), sum(len(c.STRATEGIES) for c in classes.values())


def test_readme_attack_and_strategy_counts_match_registry():
    categories, strategies = _ground_truth()
    text = README.read_text()
    # Every "<N> attack categories" and "<M> strategies" claim must be current.
    for n in re.findall(r"(\d+)\s+attack categories", text):
        assert int(n) == categories, f"README says {n} attack categories; registry has {categories}"
    for m in re.findall(r"(\d+)\s+(?:strategies total|multi-turn strategies)", text):
        assert int(m) == strategies, f"README says {m} strategies; registry has {strategies}"


def test_readme_has_no_retired_grade_vocabulary():
    text = README.read_text()
    # The Safe / At Risk grade model is retired; "Content Safety" (a vendor name)
    # is the only allowed "Safe" substring.
    assert "At Risk" not in text
    assert "Resilience Grade" not in text
