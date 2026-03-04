"""Configuration loading: .env, API keys, YAML profiles."""

from __future__ import annotations

import os
from pathlib import Path

import yaml
from dotenv import load_dotenv


def load_env() -> None:
    """Load environment variables from .env file."""
    load_dotenv()


def get_api_key(provider: str = "openai") -> str | None:
    """Return the best available API key.

    Priority: PROBEAGENT_API_KEY > OPENAI_API_KEY > AZURE_OPENAI_API_KEY
    """
    key = os.environ.get("PROBEAGENT_API_KEY")
    if key:
        return key
    if provider == "openai":
        return os.environ.get("OPENAI_API_KEY")
    if provider == "azure":
        return os.environ.get("AZURE_OPENAI_API_KEY")
    return os.environ.get("OPENAI_API_KEY") or os.environ.get("AZURE_OPENAI_API_KEY")


_BUNDLED_PROFILES = Path(__file__).resolve().parent.parent.parent.parent / "profiles"


def _profile_search_paths(name: str) -> list[Path]:
    """Return ordered list of paths to search for a profile."""
    filename = f"{name}.yaml" if not name.endswith(".yaml") else name
    cwd = Path.cwd()
    home_dir = Path.home() / ".probeagent" / "profiles"
    return [
        cwd / filename,
        cwd / "profiles" / filename,
        home_dir / filename,
        _BUNDLED_PROFILES / filename,
    ]


def load_profile(name: str) -> dict:
    """Load a YAML attack profile by name.

    Search order: CWD > CWD/profiles/ > ~/.probeagent/profiles/ > bundled profiles/
    """
    for path in _profile_search_paths(name):
        if path.is_file():
            with open(path) as f:
                return yaml.safe_load(f)
    raise FileNotFoundError(
        f"Profile '{name}' not found. Searched:\n"
        + "\n".join(f"  - {p}" for p in _profile_search_paths(name))
    )


_DEFAULT_CONFIG_TEMPLATE = """\
# ProbeAgent configuration
# See https://github.com/sumamovva/probeagent for docs

# Default attack profile
profile: quick

# Attacker LLM model
attacker_model: gpt-4

# Request timeout in seconds
timeout: 30

# Output format: terminal, markdown, json
output_format: terminal
"""


def write_default_config(directory: Path | None = None) -> Path:
    """Write a default .probeagent.yaml config template.

    Returns the path to the created file.
    """
    target_dir = directory or Path.cwd()
    config_path = target_dir / ".probeagent.yaml"
    config_path.write_text(_DEFAULT_CONFIG_TEMPLATE)
    return config_path
