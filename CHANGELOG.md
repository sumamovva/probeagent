# Changelog

All notable changes to ProbeAgent are documented in this file.

Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
Versioning follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.4] - 2026-03-17

### Fixed
- README: replaced Mermaid diagram with text (renders on PyPI)
- README: corrected strategy count (79 → 85), quick profile description, list-attacks description
- README: removed broken CI badge, added Python version requirement
- CLI: fixed wrong package name in game install error messages (`probeagent` → `probeagent-ai`)
- CLI: added guard for missing `tools/demo_email_agent.py` when using `--live`
- Quick profile YAML comment corrected (3 → 5 attacks)

### Added
- Strategy-level parallelism: `--parallel` now runs strategies within each category concurrently
- Target `clone()` method for independent concurrent strategy execution
- Graceful fallback to sequential mode for targets without `clone()` support

## [0.1.3] - 2026-03-10

### Added
- **Agentic Exploitation** attack category (CRITICAL) — 10 strategies mapped to real CVEs targeting AI agent execution surfaces: SSRF, command injection, path traversal, env manipulation, SSH flag injection, tool path hijacking, Unicode prompt breaking, supply chain memory persistence
- Agentic exploitation detection patterns in response analyzer
- CVE attribution table in ATTRIBUTION.md (OpenClaw CVE Research)

### Changed
- Total attack categories: 11 → 12
- Total strategies: 69 → 85
- Standard and thorough profiles now include agentic exploitation

## [0.1.2] - 2026-03-03

### Added
- `--header` / `-H` flag for authenticated targets
- Social engineering research attribution (Cialdini, Susan Forward)
- PyPI badges, architecture diagram in README

## [0.1.1] - 2026-02-28

### Added
- First PyPI release as `probeagent-ai`
- 12 attack categories, 85 strategies
- HTTP, OpenClaw, and Mock target adapters
- Sequential and parallel execution
- Terminal, Markdown, and JSON report formats
- Tactical Display UI
- PyRIT integration (evasion converters + red team mode)
- Quick, standard, and thorough attack profiles

[0.1.4]: https://github.com/sumamovva/probeagent/compare/v0.1.3...v0.1.4
[0.1.3]: https://github.com/sumamovva/probeagent/compare/v0.1.2...v0.1.3
[0.1.2]: https://github.com/sumamovva/probeagent/compare/v0.1.1...v0.1.2
[0.1.1]: https://github.com/sumamovva/probeagent/releases/tag/v0.1.1
