---
name: probeagent-build-test-and-release
description: >
  Run the tests, lint, commit, and cut a release for ProbeAgent (the probeagent-ai
  package). LOAD THIS before running pytest/ruff, before any `git commit`, before
  bumping the version, or before publishing to PyPI. Encodes the non-obvious gotchas:
  the pre-commit hook hangs so commits need --no-verify, commits must carry NO
  AI-attribution trailer, the version lives in three files, and PyPI publishing fires
  off a GitHub Release and is irreversible.
---

# ProbeAgent — build, test, commit, release

**When NOT to use:** if the working copy is reading empty/hanging, stop and use
[[probeagent-filesystem-wedge]] first — a wedged file will make tests fail on phantom bugs.

## Test

Run **once, in the foreground**. No parallel runs, no fan-out (the filesystem wedges
under concurrent reads).
```bash
.venv/bin/python -m pytest -q
# if the editable .pth is wedged (import errors) or you just cleared __pycache__:
PYTHONPATH=src .venv/bin/python -m pytest -q -p no:cacheprovider
```
Expected today: **433 passed, 4 skipped**. CI (`.github/workflows/ci.yml`) runs the same
suite + ruff on Python 3.10–3.13.

## Lint & format
```bash
.venv/bin/ruff check src/ tests/          # must say "All checks passed!"
.venv/bin/ruff format --check src/ tests/ # must be clean
.venv/bin/ruff format src/ tests/         # apply formatting if the check failed
```

## Commit

Two hard rules:
1. **The pre-commit hook hangs** on a network fetch. Always `git commit --no-verify`.
2. **No AI-attribution.** Never add `Co-Authored-By:` or any "generated with" trailer.
```bash
git add -A
git commit --no-verify -m "…"
git push origin main         # main is push-protected but the owner can bypass; this is expected
```

## Version bump (three files must agree)
- `pyproject.toml` → `version = "X.Y.Z"`
- `src/probeagent/__init__.py` → `__version__ = "X.Y.Z"`
- `CHANGELOG.md` → a new `## [X.Y.Z] - YYYY-MM-DD` heading (Keep a Changelog format, newest on top)

The JSON report embeds `__version__` as `probeagent_version`, and `tests/test_cli.py`
asserts it — so a mismatch fails tests. SemVer: new target type / feature = minor bump.

## Release to PyPI (IRREVERSIBLE — confirm with the user first)

Publishing is driven by a **GitHub Release**, not a manual upload:
`.github/workflows/publish.yml` triggers on `release: published` and uses PyPI **trusted
publishing** (OIDC, `pypa/gh-action-pypi-publish`). A PyPI version can be *yanked* but
never deleted or reused.

Verify the artifact before releasing:
```bash
rm -rf dist && uv build                                  # wheel + sdist
uvx twine check dist/*                                    # metadata/render must PASS
# clean-install smoke test in a throwaway venv (proves packaging, esp. bundled profiles):
V=<scratchpad>/smoke; uv venv --python 3.12 "$V"
uv pip install --python "$V/bin/python" dist/probeagent_ai-*.whl
"$V/bin/probeagent" --version
cd <scratchpad> && "$V/bin/probeagent" attack mock://vulnerable --target-type mock -p quick -o json -f r.json --fail-on never
```
Then, only after user confirmation:
```bash
gh release create vX.Y.Z --title "vX.Y.Z — …" --notes-file <notes.md> --target main
gh run watch "$(gh run list --workflow=publish.yml -L1 --json databaseId -q '.[0].databaseId')" --exit-status
curl -s https://pypi.org/pypi/probeagent-ai/json | python -c "import sys,json;print(json.load(sys.stdin)['info']['version'])"
```

## Provenance & maintenance
- Written 2026-07-12 during the 0.3.0 release (published to PyPI via this exact flow).
- Re-verify counts drift: run pytest and note the pass count; update the number above.
- Re-verify the release mechanism: `cat .github/workflows/publish.yml` (trigger + action).
- Related: [[probeagent-attacks-and-registry]] (the count guardrail that blocks release if
  README and registry disagree), [[probeagent-repo-conventions]] (commit/license rules).
