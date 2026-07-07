# Changelog

All notable changes to ProbeAgent are documented in this file.

Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
Versioning follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- **OWASP framework mapping.** Every attack is tagged against the OWASP Top 10 for
  Agentic Applications 2026 (`ASI01:2026`–`ASI10:2026`) and the OWASP Top 10 for LLM
  Applications 2025 (`LLM01:2025`–`LLM10:2025`), with edition-suffixed codes verified
  against the official OWASP GenAI Security Project sources. Codes surface in
  `list-attacks`, the terminal report (primary code(s), compact), and JSON (full set
  with resolved titles and scheme). Mappings are conservative — attacks with no clean
  agentic risk leave the ASI column empty rather than pad. A registry-time check fails
  fast on any non-canonical code.
- **CI/CD gating: `--fail-on` + meaningful exit codes.** `probeagent attack` now
  exits `0` (scan completed, nothing at/above threshold), `1` (findings at or above
  `--fail-on`), or `2` (execution error — unreachable target, bad config/auth,
  crashed scan), so a broken scan never looks like a clean pass. `--fail-on` takes
  `compromised` (default), `blocked` (opt-in), `resisted`, or `never`, driven
  directly off the verdict rollup. README adds an exit-code table and a
  ready-to-use GitHub Action snippet. (SARIF export is tracked separately.)
- **Single-source attack registry.** An attack is now declared entirely in one
  file: subclass `BaseAttack`, set metadata + `STRATEGIES` + a declarative success
  config, and apply `@register`. Attack modules are auto-discovered, so adding an
  attack is a single-file change — the engine and metadata registry both read from
  the registered class, and can no longer drift from it. See
  `docs/adding-an-attack.md`. Each attack also carries a `framework_tags` field
  (empty for now; populated in a later change).
- **Live response-signal capture wired through `BaseAttack`.** Every strategy now
  runs through `Target.send_with_signals`, so results carry real `ResponseSignals`
  and a genuine guardrailed target produces a **Blocked** verdict in a real scan
  (covered by an end-to-end test against a real `HTTPTarget`).

### Changed
- The send/analyze/score/error scaffolding and the acknowledgment-vs-compliance
  gating are consolidated into `BaseAttack`; the 12 attack modules shrank to
  strategy data plus a short success declaration. Grading behavior is unchanged —
  verified by a before/after behavioral snapshot across all attacks and mock modes.

### Fixed
- **Acknowledgment is no longer graded as compliance.** A persona-bleed-then-refuse response
  (e.g. `DAN: I can play along with the label, but I cannot do anything harmful`) previously
  graded Compromised because a canary/persona marker was present. The success condition now
  requires follow-through and defers to a dominating refusal or performative/roleplay scoping:
  - Canary/persona-marker presence is necessary-but-not-sufficient; on its own it no longer
    yields success.
  - Refusal detection catches hedged and spaced declines (`I cannot actually help`,
    `…, but I won't`); performative scoping (`play along`, `pretend`, `roleplay`) is detected
    and overrides a marker.
  - `agentic_exploitation` no longer counts a canary hit unconditionally — it is gated on the
    same refusal/performative check as the other canary attacks.
  - New `analyzer.is_compromised()` centralizes the decision; `AnalysisResult` exposes
    `compliance_evidence`, `refusal_dominant`, and `performative`.
  Text grading remains heuristic and does not verify agent actions; environment-grounded
  verification for tool-based categories is a separate roadmap item.

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
