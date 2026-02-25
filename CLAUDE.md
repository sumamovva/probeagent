# ProbeAgent - Build Instructions

## Overview
ProbeAgent is an offensive security testing CLI for AI agents. Attack your AI agent, get a resilience grade (Safe / At Risk / Compromised).

## Project Structure
- `src/probeagent/` - Main source code (src layout)
- `src/probeagent/cli.py` - Typer CLI entry point
- `src/probeagent/core/` - Models, scoring, reporting, engine, analyzer
- `src/probeagent/targets/` - Target adapters (HTTP, OpenClaw, MCP stub)
- `src/probeagent/attacks/` - Attack modules (prompt injection, credential exfil, goal hijacking, tool misuse, data exfil)
- `src/probeagent/utils/` - Config, env loading
- `profiles/` - YAML attack profiles (quick, standard, thorough)
- `tests/` - pytest test suite (121 tests)

## Development Commands
- Install: `uv pip install -e ".[dev]"` (or `pip install -e ".[dev]"`)
- Tests: `.venv/bin/python -m pytest tests/ -v`
- Lint: `.venv/bin/ruff check src/ tests/`
- Format: `.venv/bin/ruff format src/ tests/`
- Note: After model changes, may need to recreate venv: `rm -rf .venv && uv venv --python 3.12 .venv && uv pip install -e ".[dev]"`

## Key Conventions
- All async code uses `httpx` for HTTP, `asyncio` for concurrency
- CLI uses `typer` with `rich` for output
- Data models are plain dataclasses (not PyRIT types)
- Attack profiles are YAML files loaded from CWD > CWD/profiles/ > ~/.probeagent/profiles/ > bundled
- Grading: Safe (nothing succeeded), At Risk (low/medium severity), Compromised (high/critical)
- Response analysis is heuristic-based (regex patterns for refusals, secrets, compliance, system prompt leaks)
- Target types: `http` (generic HTTP/JSON API), `openclaw` (OpenClaw WebChat API)
- CLI flag: `--target-type http|openclaw`

## Architecture
- `core/analyzer.py` — Heuristic response analysis (refusal detection, secret detection, canary checking)
- `core/engine.py` — AttackEngine orchestrates all attacks, creates target from config.target_type
- `core/scoring.py` — ResilienceScore calculation (Safe/At Risk/Compromised)
- `core/reporter.py` — Terminal (Rich), Markdown, JSON report formats
- `targets/base.py` — Target ABC (send, validate, close)
- `targets/http_target.py` — Generic HTTP with format auto-detection
- `targets/openclaw_target.py` — OpenClaw WebChat HTTP adapter
- `attacks/base.py` — BaseAttack ABC with strategy pattern
