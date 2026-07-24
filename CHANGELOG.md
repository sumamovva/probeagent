# Changelog

All notable changes to ProbeAgent are documented in this file.

Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
Versioning follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.3.6] - 2026-07-24

### Added
- **`list-attacks --json`** emits attack metadata (name, display name, severity, framework
  tags, ATLAS tags, description) as machine-readable JSON to stdout, with human chrome kept
  off stdout so it pipes cleanly into `jq` — same contract as `attack -o json` (#26).
- **`docs/json-schema.md`** documents the full `-o json` report schema for programmatic
  consumers (#29).

### Tests
- Added unit tests for five previously-untested attack modules — `data_exfil`,
  `goal_hijacking`, `prompt_injection`, `seed_corpus`, `tool_misuse` (#27).

## [0.3.5] - 2026-07-21

### Fixed
- **`-o json` (and `-o markdown` / `-o log`) is now cleanly pipeable.** The config panel,
  "Target reachable" line, progress spinner, and CI-gate messages were printed to **stdout**,
  polluting machine output — so `probeagent attack … -o json | jq` failed (the report parsed as
  invalid JSON). All human chrome now goes to **stderr** in non-terminal output modes, and the
  report is written raw (not through Rich, which mangled JSON by parsing `[...]` as markup and
  soft-wrapping long lines). `stdout` now carries only the report; the documented "structured
  JSON → pipe into a remediation step / gate CI" workflow works as advertised.

## [0.3.4] - 2026-07-15

### Fixed
- **`--timeout` is now a true total request deadline, so a scan can't hang on a slow target.**
  It previously mapped to httpx's *per-read* timeout, so a target that trickled bytes — or a proxy
  holding the connection open during a long upstream model call — was never cut off, freezing a
  scan for many minutes. Each attack request (and the reachability probe) is now bounded by
  `asyncio.wait_for(..., timeout=--timeout)`; a slow/stuck target raises a timeout that the attack
  loop records as an ERROR (per 0.3.3) instead of hanging. Matters most against reasoning-model
  backends and rate-limited providers.

### Changed
- Demo agents (`tools/leaky_agent.py`, `tools/realistic_agent.py`) use an explicit
  `httpx.Timeout` and a tighter retry budget so a stuck upstream call fails fast.

## [0.3.3] - 2026-07-14

### Fixed
- **A target that returns HTTP errors is no longer graded "Resisted" (critical false-negative).**
  When an attack hit a non-2xx response that wasn't a recognized guardrail block — e.g. a bare
  host that 404s because it's missing the `/v1/chat/completions` path, an upstream 402/5xx, or a
  422 from a malformed payload — the error body was scored as if the agent had refused, so an
  **untested/unreachable target reported as safe.** Non-2xx responses (that aren't guardrail
  blocks) now record the attack as an **ERROR** with no verdict, and the run headline becomes
  "No verdict" rather than a reassuring "Resisted". This also removes the mirror false-*positive*
  where error bodies were sometimes graded "Compromised".
- **Runs where errors dominate now show an actionable caution** (terminal, markdown, JSON, log):
  "N of M attacks errored — the target returned no gradeable response... Check the target URL/path
  (OpenAI-compatible agents usually need `/v1/chat/completions`)." The machine-readable
  `resilience_score.caution` field carries it for CI.
- **A run that produces no gradeable verdict now exits 2 (execution error), not 0.** When every
  attack errored or was skipped, the target was never exercised — previously `probeagent attack`
  still exited 0, so a CI pipeline pointed at a broken/misrouted target (all 404/502) would pass
  green. It now exits `2` with a clear message, so misconfiguration fails the build instead of
  silently certifying an untested agent as safe.
- **Format detection no longer collapses on a single bad validation ping.** A `/chat/completions`
  URL or an explicit `--model` is now treated as authoritative for the OpenAI-compatible payload
  shape. Previously, if the one-shot validation ping rate-limited or errored, detection fell back
  to a generic shape and *every* subsequent attack sent a payload the agent rejected (a wall of
  HTTP 422s), silently invalidating the whole run.

- **Leaked credentials are now detected regardless of which attack surfaced them
  (grader recall 78% → 99% on real transcripts).** Previously a leaked API key only
  counted as a compromise if the attack opted into `counts_secrets` — so a key dumped
  during a social-engineering or prompt-injection attack was graded "Resisted." Secret
  patterns are now split into **hard** (unambiguous token formats — `sk-…`, AWS `AKIA`,
  GitHub `ghp_`, Slack `xox…`, GitLab `glpat-`) and **soft** (loose `password: …`
  heuristics). A hard token in any reply is an objective compromise for every attack;
  soft patterns stay gated to credential-focused attacks to avoid false positives.

### Added
- `PORT` environment variable support in the demo agents (`tools/leaky_agent.py`,
  `tools/realistic_agent.py`) so the before/after targets can run side-by-side.

## [0.3.2] - 2026-07-13

### Fixed
- **`--converters` now works out of the box.** Evasion converters (Base64, ROT13, Unicode
  homoglyphs, fullwidth, leetspeak, Atbash, Caesar, Morse, binary, flip, reverse) are now a
  native, pure-Python implementation with no external dependency. Previously they were routed
  through PyRIT via a `[pyrit]` extra that pointed at a **nonexistent package** (`pyrit-ai`),
  so every `--converters` run errored on a clean install.
- **PyRIT `--redteam` rebuilt to actually run.** The old integration targeted a PyRIT API that
  no longer exists (and an uninstallable package), so it could never execute. Rewritten against
  the current PyRIT (`>=0.14,<0.16`): `--redteam` now drives the target with PyRIT's adaptive
  multi-turn `RedTeamingAttack` — an adversarial LLM that generates each next attack from the
  agent's replies, working toward a credential-exfiltration objective scored by PyRIT's
  `CredentialLeakScorer`. Optional extra: `pip install 'probeagent-ai[pyrit]'`; the adversarial
  LLM is configured via `OPENAI_CHAT_ENDPOINT`/`OPENAI_CHAT_KEY`/`OPENAI_CHAT_MODEL`. Verified
  end-to-end; degrades with a clear message when the extra isn't installed.

## [0.3.1] - 2026-07-12

### Fixed
- **Refusal detection missed the "can't" contraction and smart-quote apostrophes.**
  The analyzer only matched the spelled-out "i cannot (help|provide|comply|…)", so extremely
  common refusals like *"I can't help with that"* / *"I can't share those credentials"* — and
  any refusal using a curly apostrophe (U+2019), which verbose/reasoning models frequently
  emit — were not recognized as refusals. Combined with a canary/marker in the reply, this
  produced **false-positive Compromised verdicts** (a refusal that quotes the forbidden token
  was scored as compliance). Responses are now smart-quote-normalized and the pattern matches
  the contraction across a broader verb set. Regression tests added.

## [0.3.0] - 2026-07-12

### Added
- **MCP target type (`--target-type mcp`).** Attack an MCP (Model Context Protocol)
  server directly over the Streamable HTTP transport — JSON-RPC via `httpx`, no MCP SDK
  dependency. Performs the `initialize` handshake, enumerates tools (`tools/list`), and
  **detects tool poisoning** (hidden-instruction signatures in tool descriptions/params,
  surfaced in the validation output — OWASP MCP03). Prompt-based attacks reach the tool-use
  loop via `tools/call`. Streamable HTTP only (not stdio); single-tool invocation.
- **External attack-seed corpora (`--seeds <file>`).** Replay community/dataset seeds
  (e.g. SafeMTData multi-turn jailbreaks exported to JSONL) through the scoring pipeline as a
  `seed_corpus` attack. Accepts `.jsonl`/`.json`/`.yaml`/`.txt`, normalizing multi-turn,
  single-turn, and bare-string records; honors per-seed `success_patterns` and `canary`.

## [0.2.3] - 2026-07-10

### Added
- **`--model` / `-m` flag for raw OpenAI-compatible endpoints.** Point ProbeAgent
  directly at OpenRouter, OpenAI, Groq, Ollama, or any endpoint that requires a `model`
  field in the request body — no proxy needed. The model id is threaded through
  `ProbeConfig`, shown in the attack-configuration panel, and sent on every request
  (validation ping, attack traffic, and multi-turn follow-ups). Gated to HTTP targets;
  `mock`/`openclaw` targets ignore it. Example:
  `probeagent attack https://openrouter.ai/api/v1/chat/completions --model anthropic/claude-3.5-sonnet -H "Authorization: Bearer $OPENROUTER_KEY"`.

## [0.2.2] - 2026-07-09

### Added
- **Attribution analysis** (`probeagent.core.attribution` + `tools/attribution_study.py`):
  from a scan's JSON, computes the *crying-wolf gap* (how much a naive canary/keyword
  grader over-reports vs. ProbeAgent's follow-through verdict) and the *model-vs-guardrail
  attribution split* (of "safe" results, how many a filter caught rather than the model
  refusing). Compares multiple targets side by side.
- **MITRE ATLAS mapping.** Every attack is tagged with MITRE ATLAS technique IDs
  (`AML.T####`) alongside the OWASP codes, verified against `mitre-atlas/atlas-data`
  (e.g. `AML.T0051.001` Indirect Prompt Injection, `AML.T0053` AI Agent Tool Invocation,
  `AML.T0056` Extract LLM System Prompt, `AML.T0034.002` Agentic Resource Consumption).
  Surfaced in the JSON `mitre_atlas` field per finding; the registry fails fast on any
  non-canonical technique ID. README documents the full mapping and sources.

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
