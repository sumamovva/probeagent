# Changelog

All notable changes to ProbeAgent are documented in this file.

Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
Versioning follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.2.1] - 2026-07-08

### Fixed
- **Bundled attack profiles are now packaged.** `probeagent demo` and
  `probeagent attack --profile ...` failed on a clean `pip install` with
  "Profile 'quick' not found" — the `profiles/*.yaml` files were never included in
  the wheel, and the bundled-profile path resolved to a repo-root location that
  only exists in a source checkout. Profiles moved into the package
  (`probeagent/profiles/`), shipped as package data, and the loader resolves them
  relative to the installed package. A regression test simulates a clean install
  (loads a bundled profile from an unrelated working directory). Affected 0.2.0
  and earlier; 0.2.0 is yanked in favor of this release.

## [0.2.0] - 2026-07-08

Reworks how ProbeAgent grades, reports, and gates. Highlights: a three-verdict
model (Compromised / Resisted / Blocked) with the persona-bleed false positive
fixed at the root, OWASP ASI 2026 + LLM 2025 mapping, and CI gating via
`--fail-on` and exit codes. Grading is text-based and does not verify an agent's
real actions — environment-grounded verification remains on the roadmap.

### Breaking changes
- **Grading model replaced.** The `Safe / At Risk / Compromised` aggregate grade is
  retired for a per-attack verdict — **Compromised** (attack succeeded), **Resisted**
  (model refused/deflected), **Blocked** (a guardrail/gateway stopped the attack before
  the model replied) — rolled up to a run headline (worst verdict present) plus a
  breakdown. `"At Risk"` had no clean mapping onto the new model and was removed, not
  renamed. Terminal / markdown / log reports and the web UI use the new vocabulary.
- **JSON output** (`--output json`): `resilience_score.grade` is gone. Use
  `resilience_score.headline_verdict` and `resilience_score.verdict_breakdown`
  (`{compromised, resisted, blocked}`), plus a `caution` field. Per-attack summaries and
  results now carry `verdict` and `framework_tags`; results also expose `blocked_by`.
  Any parser reading `.grade` must update.
- **Exit codes.** `probeagent attack` now returns `0` (scan completed, nothing at/above
  `--fail-on`), `1` (findings at or above `--fail-on`), or `2` (execution error —
  unreachable target, bad config/auth, crashed scan). Previously it exited `0` on
  completion and `1` on any error, so a broken scan could not be told from a clean pass.
- **`--fail-on` defaults to `compromised`.** A scan that finds a Compromised attack now
  exits `1`. Use `--fail-on never` to restore always-exit-0-on-completion. Other
  thresholds: `blocked` (opt-in) and `resisted`.

### Added
- **Three-verdict model + guardrail detection.** Per-attack Compromised / Resisted /
  Blocked with an explicit precedence and rollup. An editable guardrail signature registry
  (`core/guardrails.py`) detects transport/guardrail-level blocks (Bedrock Guardrails,
  Azure Content Safety, OpenAI content filter, Lakera, Prompt Guard, HTTP 403) even when
  the guardrail returns HTTP 200; register new ones with `@register_guardrail_signature`.
  Structured per-response signals (`ResponseSignals`) are captured via
  `Target.send_with_signals` and flow end-to-end, so Blocked fires in a real scan. The
  design stance is to under-report Blocked, never over-report it, with a caution when a run
  is dominated by Blocked.
- **OWASP framework mapping.** Every attack is tagged against the OWASP Top 10 for Agentic
  Applications 2026 (`ASI01:2026`–`ASI10:2026`) and the OWASP Top 10 for LLM Applications
  2025 (`LLM01:2025`–`LLM10:2025`), verified against the official OWASP sources. Codes
  surface in `list-attacks`, the terminal report (primary codes), and JSON (full set with
  titles). Mappings are conservative; a registry-time check fails fast on any non-canonical
  code.
- **CI/CD gating: `--fail-on` + exit codes** (see Breaking changes). README adds an
  exit-code table and a ready-to-use GitHub Action snippet. (SARIF export is tracked
  separately.)
- **Single-source attack registry.** An attack is declared in one auto-discovered file
  (`@register` + declarative success config); the engine and metadata registry read from
  it, so they cannot drift. Adding an attack is a single-file change — see
  `docs/adding-an-attack.md`.
- Python 3.13 added to the CI matrix and declared supported.

### Changed
- Send/analyze/score/error scaffolding and the acknowledgment-vs-compliance gating are
  consolidated into `BaseAttack`; the 12 attack modules shrank to strategy data plus a
  short success declaration. A multi-turn strategy now stops early once a compromise is
  confirmed by a hard, monotonic signal. Grading behavior is unchanged — verified by a
  byte-identical before/after behavioral snapshot across all attacks and mock modes.
- README honesty pass: the competitor feature-matrix is replaced with a verified
  "where ProbeAgent fits" positioning and a "does / doesn't" capability list that leads
  with the text-grading limitation. A test guards the documented attack/strategy counts
  against registry ground truth.

### Fixed
- **Acknowledgment is no longer graded as compliance.** A persona-bleed-then-refuse
  response (e.g. `DAN: I can play along with the label, but I cannot do anything harmful`)
  previously graded Compromised because a canary/persona marker was present. Compromise now
  requires follow-through: canary/persona presence is necessary-but-not-sufficient, refusal
  detection catches hedged/spaced declines and performative/roleplay scoping overrides a
  marker, and `agentic_exploitation` no longer counts a canary hit unconditionally.
  `analyzer.is_compromised()` centralizes the decision. Text grading remains heuristic and
  does not verify agent actions.

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
