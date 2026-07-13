---
name: probeagent-repo-conventions
description: >
  Follow ProbeAgent's house rules for files, licensing, packaging, changelog, and what
  belongs in the repo. LOAD THIS when creating a new source file, editing packaging
  (pyproject), writing changelog entries, or deciding whether something (esp. marketing)
  belongs in the repo at all. Prevents the common mistakes that get caught in review.
---

# ProbeAgent — repo conventions

**When NOT to use:** for commit/test/release mechanics use
[[probeagent-build-test-and-release]].

## License header on every source file

Every `.py` (and shell tool) starts with:
```python
# Copyright 2025 Suma Movva
# SPDX-License-Identifier: Apache-2.0
```
The project is **Apache 2.0** (`LICENSE`, `NOTICE`). Third-party credits go in
`ATTRIBUTION.md`.

## Keep marketing OUT of the repo

The repo stays **product-focused**. LinkedIn posts, launch copy, positioning decks, and
generated marketing reports do **not** get committed — they live in the scratchpad. Demo
*tooling* under `tools/` (functional scripts, runbooks) is fine; marketing *narrative* is not.
This is a standing decision — do not "helpfully" add a launch post or a bakeoff report to the
repo.

## Packaging (setuptools)

- Source lives under `src/`; packages found via `[tool.setuptools.packages.find] where=["src"]`.
- **Package data must be declared** or it won't ship: `[tool.setuptools.package-data]
  probeagent = ["web/*.html", "profiles/*.yaml"]`. (A missing declaration shipped a broken
  wheel once — profiles weren't packaged, so `attack --profile` failed on a clean install.)
- `tools/` and `tests/` are **not** packaged. Runtime deps in `[project.dependencies]`;
  everything else in extras: `dev`, `game`, `pyrit`, `demo`.
- Console entry point: `probeagent = "probeagent.cli:app"`.

## CHANGELOG

`CHANGELOG.md` follows **Keep a Changelog** + **SemVer**, newest version on top:
`## [X.Y.Z] - YYYY-MM-DD` then `### Added` / `### Fixed` bullets. Every release commit updates
it alongside the two version stamps (see [[probeagent-build-test-and-release]]).

## Commits & attribution

No AI-attribution/`Co-Authored-By` trailers. Commit subjects are conventional-ish
(`docs:`, `test:`, `Release X.Y.Z: …`). Marketing decisions and cross-session facts live in
the user's memory, not the repo.

## Provenance & maintenance
- Written 2026-07-12. Re-verify packaging data:
  `grep -A2 'package-data' pyproject.toml` and `unzip -l dist/*.whl | grep -E 'profiles/|web/'`.
- Re-verify a header sample: `head -2 src/probeagent/cli.py`.
- Related: [[probeagent-build-test-and-release]], [[probeagent-attacks-and-registry]].
