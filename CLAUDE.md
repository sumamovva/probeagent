# ProbeAgent - Build Instructions

## Overview
ProbeAgent is an offensive security testing CLI for AI agents, wrapping Microsoft's PyRIT framework.

## Project Structure
- `src/probeagent/` - Main source code (src layout)
- `src/probeagent/cli.py` - Typer CLI entry point
- `src/probeagent/core/` - Models, scoring, reporting, engine
- `src/probeagent/targets/` - Target adapters (HTTP, OpenClaw, MCP)
- `src/probeagent/attacks/` - Attack modules and registry
- `src/probeagent/utils/` - Config, env loading
- `profiles/` - YAML attack profiles (quick, standard, thorough)
- `tests/` - pytest test suite

## Development Commands
- Install: `pip install -e ".[dev]"`
- Tests: `python -m pytest tests/ -v`
- Lint: `ruff check src/ tests/`
- Format: `ruff format src/ tests/`

## Key Conventions
- All async code uses `httpx` for HTTP, `asyncio` for concurrency
- CLI uses `typer` with `rich` for output
- Data models are plain dataclasses (not PyRIT types)
- PyRIT integration happens at the engine boundary (Phase 2)
- Attack profiles are YAML files loaded from CWD > CWD/profiles/ > ~/.probeagent/profiles/ > bundled

## Phase Status
- Phase 1 (current): Scaffolding, CLI, HTTP target, scoring, reporting
- Phase 2 (next): PyRIT-powered attack modules
- Phase 3 (future): OpenClaw + MCP targets
