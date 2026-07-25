# Copyright 2025 Suma Movva
# SPDX-License-Identifier: Apache-2.0

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


# Profiles are bundled inside the package (src/probeagent/profiles/), so this
# resolves correctly whether running from a source checkout or an installed wheel.
_BUNDLED_PROFILES = Path(__file__).resolve().parent.parent / "profiles"


def _validate_profile_name(name: str) -> None:
    """Reject profile names that could escape the profile search directories.

    Profiles are looked up by bare name across a fixed set of directories, so a
    valid name is a single filename with no path component. Rejecting separators,
    parent refs, and absolute paths closes a path-traversal vector — important
    because ``load_profile`` is reachable from the ``game`` web server with a
    request-supplied profile name (see web/server.py).
    """
    if (
        not name
        or name in (".", "..")
        or "/" in name
        or "\\" in name
        or os.sep in name
        or (os.altsep and os.altsep in name)
        or Path(name).is_absolute()
    ):
        raise ValueError(
            f"Invalid profile name {name!r}: must be a bare name without path separators."
        )


def _profile_roots() -> list[Path]:
    """Directories a profile may be loaded from, in search order."""
    return [
        Path.cwd(),
        Path.cwd() / "profiles",
        Path.home() / ".probeagent" / "profiles",
        _BUNDLED_PROFILES,
    ]


def _safe_filename(name: str) -> str:
    """Validated, directory-stripped profile filename (``<name>.yaml``)."""
    _validate_profile_name(name)
    safe_name = os.path.basename(name)
    return f"{safe_name}.yaml" if not safe_name.endswith(".yaml") else safe_name


def _profile_search_paths(name: str) -> list[Path]:
    """Return ordered list of paths to search for a profile."""
    filename = _safe_filename(name)
    return [root / filename for root in _profile_roots()]


def load_profile(name: str) -> dict:
    """Load a YAML attack profile by name.

    Search order: CWD > CWD/profiles/ > ~/.probeagent/profiles/ > bundled profiles/
    """
    filename = _safe_filename(name)
    for root in _profile_roots():
        real_root = os.path.realpath(root)
        candidate = os.path.realpath(os.path.join(real_root, filename))
        # Refuse any candidate that resolves outside its intended root — a
        # containment check on the exact path handed to open(), independent of
        # the name validation above (defense in depth).
        if os.path.commonpath([real_root, candidate]) != real_root:
            continue
        if os.path.isfile(candidate):
            with open(candidate) as f:
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
