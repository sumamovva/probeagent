---
name: probeagent-targets-and-test-isolation
description: >
  Work with ProbeAgent's target adapters (http, openclaw, mock, mcp) and write/​fix its
  tests. LOAD THIS when touching src/probeagent/targets/, adding target-facing tests,
  mocking HTTP with respx, testing the async MCP path, or debugging a test that passes
  alone but fails in the full suite. Encodes the mock schemes, the respx pattern, and the
  SeedCorpusAttack.STRATEGIES global-mutation trap that silently breaks unrelated tests.
---

# ProbeAgent — targets & test isolation

**When NOT to use:** for attack definitions/counts use [[probeagent-attacks-and-registry]];
for verdict/JSON semantics use [[probeagent-verdicts-and-json-contract]].

## Target types (`--target-type`)

- `http` (default) — auto-detects OpenAI chat (`{"messages":[…]}`→`{"choices":[…]}`),
  simple JSON (`{"prompt":…}`→`{"response":…}`, also accepts text/content/output/result),
  or plain text. `--model`/`-m` adds a `model` field for raw OpenAI-compatible endpoints.
- `openclaw` — n8n webhook wire format (`action`/`chatInput`/`sessionId`). NOT the OpenClaw
  OpenAI gateway (use `http` for `/v1/chat/completions`).
- `mock` — no network, no key. Schemes: `mock://vulnerable` (grades Compromised),
  `mock://moderate` (mixed), `mock://hardened` (Resisted). Use these in tests and demos.
- `mcp` — Model Context Protocol over Streamable HTTP; JSON-RPC via `httpx` (no MCP SDK).
  Does the `initialize` handshake, `tools/list`, detects **tool poisoning** (hidden
  instructions in tool descriptions/params, OWASP MCP03), and attacks via `tools/call`.

## Testing patterns

- HTTP is mocked with **respx**: `@respx.mock` + `respx.post(URL).mock(return_value=httpx.Response(…))`
  or `.mock(side_effect=handler)`. The mock must answer **every** POST the code makes — for
  MCP that means `initialize`, `notifications/initialized` (return 202), `tools/list`, and
  `tools/call`, dispatched on the JSON-RPC `method`.
- Async tests use **pytest-asyncio** (`asyncio_mode = "auto"` in pyproject); mark with
  `@pytest.mark.asyncio`. Always `await target.close()`.
- Run the suite per [[probeagent-build-test-and-release]] (one foreground run).

## The isolation trap (a real bug this caused)

The CLI `--seeds` path sets a **class global**: `SeedCorpusAttack.STRATEGIES = load_seeds(...)`
and never restores it. Any test that exercises that path (e.g. `test_cli.py::test_attack_with_seeds`)
**must save and restore it**, or later tests see `seed_corpus` as a strategy-bearing 13th
category and fail (notably the `test_docs.py` count guardrail). Symptom: a test passes in
isolation (`pytest -k …`) but the full run reports "registry has 13". Fix pattern:

```python
from probeagent.attacks.seed_corpus import SeedCorpusAttack
original = SeedCorpusAttack.STRATEGIES
try:
    ...  # run the CLI --seeds path
finally:
    SeedCorpusAttack.STRATEGIES = original
```

Any future code that mutates a registered attack's class attributes at runtime needs the
same save/restore in its tests.

## Live targets for manual/e2e testing (not unit tests)

- `tools/leaky_agent.py` — deliberately-vulnerable OpenAI-compatible agent. Standalone
  (canned responses, no key) or backed by a real model via `OPENAI_BASE_URL`/`OPENAI_API_KEY`/`MODEL`.
  Serves `/v1/chat/completions` on `:8800`. This is the rig for [[probeagent-model-bakeoff]].
- `tools/demo_email_agent.py` — Anthropic-backed, three hardness endpoints
  (vulnerable/moderate/hardened). Needs `ANTHROPIC_API_KEY` + `[demo]` extra.

## Provenance & maintenance
- Written 2026-07-12 after fixing the seed-corpus global-mutation test pollution.
- Re-verify mock schemes: `grep -oE 'mock://[a-z]+' -r src/probeagent/targets/mock_target.py | sort -u`.
- Related: [[probeagent-attacks-and-registry]], [[probeagent-filesystem-wedge]].
