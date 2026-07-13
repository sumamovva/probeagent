---
name: probeagent-model-bakeoff
description: >
  Run the "same agent, different backing models" resistance comparison and build the
  leaderboard. LOAD THIS when asked to compare models, stress-test an agent across models,
  produce the bakeoff report, or work with tools/run_bakeoff.sh, tools/model_bakeoff.py,
  tools/leaky_agent.py, or the --model flag. Encodes the OpenRouter setup, the secret-key
  hygiene, the wedged-fs invocation, and cost control.
---

# ProbeAgent — model bakeoff

Compare how well different backing models resist the SAME attacks, by pointing one fixed
vulnerable agent (`tools/leaky_agent.py`) at each model in turn. Showcases the `--model`
flag and the "stress-test your agent across models" pitch.

**When NOT to use:** for interpreting the verdicts themselves use
[[probeagent-verdicts-and-json-contract]]; for the wedged-fs `PYTHONPATH=src` reason see
[[probeagent-filesystem-wedge]].

## Tools

- `tools/leaky_agent.py` — fixed vulnerable OpenAI-compatible agent on `:8800`. Backed by a
  real model via `OPENAI_BASE_URL` + `OPENAI_API_KEY` + `MODEL`. Deterministic by default
  (`temperature=0`; override with `TEMPERATURE=…`). Needs `fastapi`+`uvicorn`.
- `tools/run_bakeoff.sh` — sweeps ≥2 models: for each, starts the agent backed by that model,
  scans with ProbeAgent, saves JSON, then builds the leaderboard. Auto-sources `.env`.
- `tools/model_bakeoff.py` — takes `"label=path.json" …`, prints a Markdown leaderboard
  (ranked most→least resistant) + a category×model matrix + a one-line insight. Uses
  `attack_summaries` (per-category verdicts) and `resilience_score`.

## Secret-key hygiene (do this exactly)

Put the OpenRouter key in a **git-ignored `.env`** at the repo root — never on the command
line, never pasted into a transcript, never `cat`/`echo`'d:
```
OPENAI_API_KEY=sk-or-…
OPENAI_BASE_URL=https://openrouter.ai/api/v1
```
`.env` is already in `.gitignore`. `run_bakeoff.sh` sources it with `set -a; . ./.env; set +a`
and passes it to children without printing it. When verifying the key, check only that the
variable *name* is present and non-empty — never surface its value.

## Run it (on this wedged filesystem)

`probeagent` and `python` must resolve to the venv, and `PYTHONPATH=src` bypasses the wedged
editable `.pth`:
```bash
SP=<scratchpad>
PATH="$PWD/.venv/bin:$PATH" PYTHONPATH=src PROFILE=quick OUTDIR="$SP/bakeoff_out" \
  bash tools/run_bakeoff.sh "openai/gpt-5" "anthropic/claude-opus-4.8" "meta-llama/llama-3.1-8b-instruct"
```
Cost discipline: run `PROFILE=quick` (33 single-turn) first as a cheap sanity pass, then
`PROFILE=standard` (85 multi-turn) for publishable numbers. Premium models
(`anthropic/claude-fable-5` $10/$50 per M, opus, gpt-5) dominate spend; small/open models are
rounding error. Check remaining balance and per-model pricing before a big run:
```bash
curl -s https://openrouter.ai/api/v1/credits -H "Authorization: Bearer $OPENAI_API_KEY"  # total_credits - total_usage = remaining
curl -s https://openrouter.ai/api/v1/models | python -c "import sys,json;[print(m['id'],m['pricing']) for m in json.load(sys.stdin)['data']]"
```

## Validate before publishing any comparison
1. Deterministic (`temperature=0`) so re-runs match.
2. Spot-check transcripts (`attack_results[].turns`) — confirm "Compromised" is genuine
   follow-through and "Resisted" is a genuine refusal, not a grader blind spot.
3. Frame honestly: the agent is *deliberately vulnerable*, so this measures which backing
   model degrades most gracefully under a poorly-built agent — not out-of-the-box safety.
   Lead with the gradient and universal weak spots, not "model X wins."

## Provenance & maintenance
- Written 2026-07-12. leaky_agent's fake secrets are FAKE (test fixtures), not real.
- Related: [[probeagent-targets-and-test-isolation]] (leaky_agent), [[probeagent-verdicts-and-json-contract]].
