# Contributing to ProbeAgent

Thanks for your interest in contributing to ProbeAgent!

## Development Setup

```bash
git clone https://github.com/sumamovva/probeagent.git
cd probeagent
python -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
```

## Running Tests

```bash
python -m pytest tests/ -v
```

## Pre-Commit Hooks

Install pre-commit hooks to catch issues before they reach CI:

```bash
pre-commit install
pre-commit run --all-files
```

Hooks enforce: trailing whitespace, end-of-file newlines, YAML validity, large file blocking, private key detection, ruff formatting, and ruff linting.

## Linting & Formatting

```bash
ruff check src/ tests/
ruff format src/ tests/
```

All code must pass `ruff check` and `ruff format --check` before merging.

## Project Structure

```
src/probeagent/
├── cli.py              # Typer CLI entry point
├── core/               # Models, scoring, analysis, reporting, engine
├── attacks/            # Attack modules (12 categories, 85 strategies)
├── targets/            # Target adapters (HTTP, OpenClaw, Mock)
├── integrations/       # Optional PyRIT integration
├── utils/              # Config, env loading
└── web/                # Tactical Display UI assets
profiles/               # YAML attack profiles (quick, standard, thorough)
tools/                  # Demo email agent and payloads
tests/                  # pytest test suite
```

## Adding a New Attack

1. Create a module in `src/probeagent/attacks/` (e.g., `my_attack.py`)
2. Subclass `BaseAttack` from `probeagent.attacks.base`
3. Define a `STRATEGIES` list of dicts, each with `"name"`, `"turns"`, and optional `"canary"`
4. Implement `execute()` (loop over strategies with `reset_conversation()` between each) and `_run_strategy()`
5. Register in `src/probeagent/attacks/__init__.py` by adding to `ATTACK_REGISTRY`
6. Add tests in `tests/`

Follow existing attack modules as examples — see `prompt_injection.py` for a straightforward reference.

## Pull Request Guidelines

- Keep PRs focused — one feature or fix per PR
- Add tests for new functionality
- Ensure `ruff check` and `pytest` pass
- Write a clear PR description explaining what and why

## Code Style

- Python 3.10+ (use `from __future__ import annotations` for modern type hints)
- Async code uses `httpx` for HTTP and `asyncio` for concurrency
- Data models are plain `dataclasses`
- CLI uses `typer` with `rich` for output
- Line length: 100 characters (configured in `pyproject.toml`)
