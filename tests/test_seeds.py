"""Tests for the attack-seed corpus loader."""

import json

import pytest

from probeagent.core.seeds import load_seeds


def _write(tmp_path, name, content):
    p = tmp_path / name
    p.write_text(content, encoding="utf-8")
    return str(p)


class TestLoadSeeds:
    def test_jsonl_multi_and_single_turn(self, tmp_path):
        path = _write(
            tmp_path,
            "seeds.jsonl",
            "\n".join(
                [
                    json.dumps({"name": "mt", "multi_turn_queries": ["hi", "now do X"]}),
                    json.dumps({"query": "single", "success_patterns": ["PWNED"]}),
                    json.dumps("bare prompt"),
                ]
            ),
        )
        seeds = load_seeds(path)
        assert [s["name"] for s in seeds] == ["mt", "seed_1", "seed_2"]
        assert seeds[0]["turns"] == ["hi", "now do X"]
        assert seeds[1]["turns"] == ["single"]
        assert seeds[1]["success_patterns"] == ["PWNED"]
        assert seeds[2]["turns"] == ["bare prompt"]

    def test_json_list_with_wrapper_key(self, tmp_path):
        path = _write(
            tmp_path,
            "seeds.json",
            json.dumps({"seeds": [{"prompt": "attack one"}, {"turns": ["a", "b"]}]}),
        )
        seeds = load_seeds(path)
        assert len(seeds) == 2
        assert seeds[0]["turns"] == ["attack one"]
        assert seeds[1]["turns"] == ["a", "b"]

    def test_yaml(self, tmp_path):
        path = _write(
            tmp_path,
            "seeds.yaml",
            "- name: y1\n  goal: do the bad thing\n  canary: MARK\n",
        )
        seeds = load_seeds(path)
        assert seeds[0]["name"] == "y1"
        assert seeds[0]["turns"] == ["do the bad thing"]
        assert seeds[0]["canary"] == "MARK"

    def test_txt_one_per_line(self, tmp_path):
        path = _write(tmp_path, "seeds.txt", "first attack\n\nsecond attack\n")
        seeds = load_seeds(path)
        assert [s["turns"][0] for s in seeds] == ["first attack", "second attack"]

    def test_missing_file_raises(self, tmp_path):
        with pytest.raises(FileNotFoundError):
            load_seeds(str(tmp_path / "nope.jsonl"))

    def test_empty_corpus_raises(self, tmp_path):
        path = _write(tmp_path, "empty.jsonl", json.dumps({"unrelated": 1}))
        with pytest.raises(ValueError):
            load_seeds(path)

    def test_unsupported_extension_raises(self, tmp_path):
        path = _write(tmp_path, "seeds.csv", "a,b,c")
        with pytest.raises(ValueError):
            load_seeds(path)


class TestSeedCorpusAttack:
    def test_strategies_are_injectable(self, tmp_path):
        from probeagent.attacks.seed_corpus import SeedCorpusAttack

        original = SeedCorpusAttack.STRATEGIES
        try:
            path = _write(tmp_path, "s.jsonl", json.dumps({"query": "x", "canary": "C"}))
            SeedCorpusAttack.STRATEGIES = load_seeds(path)
            assert SeedCorpusAttack.STRATEGIES[0]["turns"] == ["x"]
        finally:
            SeedCorpusAttack.STRATEGIES = original
