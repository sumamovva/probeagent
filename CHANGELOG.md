# Changelog

All notable changes to ProbeAgent are documented in this file.

Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
Versioning follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Changed (breaking)
- **Grading model replaced.** The `Safe / At Risk / Compromised` aggregate grade is
  retired in favor of a three-verdict model applied per attack:
  **Compromised** (attack succeeded), **Resisted** (model refused/deflected), and
  **Blocked** (a guardrail/gateway stopped the attack before the model replied). The run
  headline is the worst verdict present plus a breakdown. The `"At Risk"` grade had no clean
  mapping onto the new model and was removed rather than renamed.
- **JSON output** (`--output json`): `resilience_score.grade` is replaced by
  `resilience_score.headline_verdict` and `resilience_score.verdict_breakdown`
  (`{compromised, resisted, blocked}`) plus an optional `caution` string. Per-attack
  summaries and results now carry a `verdict` field; results also expose `blocked_by`.
  Parsers reading `.grade` must update.
- **Tactical Display** (web UI) and terminal/markdown/log reports use the new verdict
  vocabulary.

### Added
- Guardrail signature registry (`probeagent/core/guardrails.py`): an editable,
  contributor-extendable set of signatures that detect transport/guardrail-level blocks
  (Bedrock Guardrails, Azure Content Safety, OpenAI content filter, Lakera, Prompt Guard,
  HTTP 403) even when the guardrail returns HTTP 200. Register new ones with
  `@register_guardrail_signature`.
- Structured per-response signal capture (`ResponseSignals`: status, latency, headers,
  body, `blocked_by`) via `Target.send_with_signals`, so genuine Blocked results are
  observable. The design stance is to under-report Blocked, never over-report it.
- Blocked caution in reports: when categories roll up to Blocked, the report notes the
  model was not exercised and suggests running from inside the trust boundary.

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
