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
├── attacks/            # Attack modules (12 categories, 85 strategies) — auto-discovered
├── targets/            # Target adapters (HTTP, OpenClaw, Mock, MCP)
├── integrations/       # Evasion converters + optional PyRIT red-team
├── utils/              # Config, env loading
└── web/                # Tactical Display UI assets
profiles/               # YAML attack profiles (quick, standard, thorough)
tools/                  # Demo agents, MCP server, model-bakeoff scripts
tests/                  # pytest test suite
```

## Adding a New Attack

An attack is a **single file** in `src/probeagent/attacks/`. Drop it in and it's
auto-discovered and registered — you do **not** edit the engine, `__init__.py`, or any
registry, and you do **not** implement the send/score loop (that all lives in `BaseAttack`).
Your file only declares *what to send* and *what counts as a compromise*.

1. Copy the template from **[`docs/adding-an-attack.md`](docs/adding-an-attack.md)** into
   `src/probeagent/attacks/my_attack.py`.
2. Add the `@register` decorator, subclass `BaseAttack`, and set the metadata (`name`,
   `display_name`, `severity`, `description`, `framework_tags`, `atlas_tags`).
3. Fill in `STRATEGIES` — a list of dicts, each with `"name"`, `"turns"`, and optional
   `"canary"` / `"success_patterns"`.
4. Add a test in `tests/` (see `tests/test_attack_prompt_injection.py` for the pattern). If
   you add a *whole new category*, update the "N categories / M strategies" counts in the
   README — a test (`tests/test_docs.py`) guards this.

No registry wiring needed. See `prompt_injection.py` for a minimal reference and
`docs/adding-an-attack.md` for the full guide (grading knobs, canaries, and the
acknowledgment-vs-compliance principle).

## Where to start (good first contributions)

The fastest, highest-value ways in — see the **`good first issue`** label on GitHub for
specific, scoped tasks:

- **Add an attack strategy** — one new dict in an existing category's `STRATEGIES` list
  (a fresh prompt-injection variant, a new social-engineering angle). ~10-minute PR.
- **Add an evasion converter** — a new obfuscation transform in
  `src/probeagent/integrations/converters.py` (one function + one map).
- **Close the loop with remediation** — contribute "here's the fix" guidance for an attack
  category so a finding says *how to patch it*, not just that it's compromised.
- **Add a target adapter** — wire up a new agent framework in `src/probeagent/targets/` so
  the community can test it (follow `http_target.py` / `mcp_target.py`).
- **Submit a model bakeoff** — run `tools/run_bakeoff.sh` on your own model shortlist and
  share the numbers.

Open an issue first for anything larger than a single strategy/converter, so we can point you
in the right direction.

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
