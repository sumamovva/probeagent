"""Tests for configuration loading."""

import pytest

from probeagent.utils.config import get_api_key, load_profile, write_default_config


class TestGetApiKey:
    def test_probeagent_key_priority(self, monkeypatch):
        monkeypatch.setenv("PROBEAGENT_API_KEY", "pa-key")
        monkeypatch.setenv("OPENAI_API_KEY", "oai-key")
        assert get_api_key() == "pa-key"

    def test_openai_fallback(self, monkeypatch):
        monkeypatch.delenv("PROBEAGENT_API_KEY", raising=False)
        monkeypatch.setenv("OPENAI_API_KEY", "oai-key")
        assert get_api_key("openai") == "oai-key"

    def test_azure_key(self, monkeypatch):
        monkeypatch.delenv("PROBEAGENT_API_KEY", raising=False)
        monkeypatch.setenv("AZURE_OPENAI_API_KEY", "az-key")
        assert get_api_key("azure") == "az-key"

    def test_no_key(self, monkeypatch):
        monkeypatch.delenv("PROBEAGENT_API_KEY", raising=False)
        monkeypatch.delenv("OPENAI_API_KEY", raising=False)
        monkeypatch.delenv("AZURE_OPENAI_API_KEY", raising=False)
        assert get_api_key() is None


class TestLoadProfile:
    def test_load_bundled_quick(self):
        profile = load_profile("quick")
        assert profile["name"] == "quick"
        assert "prompt_injection" in profile["attacks"]

    def test_load_bundled_standard(self):
        profile = load_profile("standard")
        assert profile["name"] == "standard"
        assert len(profile["attacks"]) == 9

    def test_load_bundled_thorough(self):
        profile = load_profile("thorough")
        assert profile["max_turns"] == 10

    def test_profile_not_found(self):
        with pytest.raises(FileNotFoundError, match="nonexistent"):
            load_profile("nonexistent")

    def test_load_from_cwd(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        profile_file = tmp_path / "custom.yaml"
        profile_file.write_text("name: custom\nattacks:\n  - prompt_injection\nmax_turns: 2\n")
        profile = load_profile("custom")
        assert profile["name"] == "custom"


class TestWriteDefaultConfig:
    def test_creates_file(self, tmp_path):
        path = write_default_config(tmp_path)
        assert path.exists()
        assert path.name == ".probeagent.yaml"
        content = path.read_text()
        assert "profile:" in content
        assert "quick" in content

    def test_default_uses_cwd(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        path = write_default_config()
        assert path.parent == tmp_path
