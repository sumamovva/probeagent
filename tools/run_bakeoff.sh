#!/usr/bin/env bash
# Model bakeoff runner — scan the SAME agent backed by several models, then build
# a resistance leaderboard. Each model is served through tools/leaky_agent.py (a
# fixed vulnerable agent), so only the backing model changes between scans.
#
# Requires: an OpenAI-compatible key + base URL (OpenRouter is easiest — one key,
# many models), and the demo deps (fastapi, uvicorn, httpx):
#   pip install 'probeagent-ai[demo]'   # or: pip install fastapi uvicorn httpx
#
# Usage:
#   export OPENAI_API_KEY=sk-or-...                       # OpenRouter (or provider) key
#   export OPENAI_BASE_URL=https://openrouter.ai/api/v1   # default if unset
#   bash tools/run_bakeoff.sh \
#     "openai/gpt-4o" \
#     "anthropic/claude-3.5-sonnet" \
#     "meta-llama/llama-3.3-70b-instruct" \
#     "mistralai/mistral-large"
#
# Output: bakeoff_out/<model>.json per model + bakeoff_out/bakeoff_report.md
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
PORT=8800
PROFILE="${PROFILE:-standard}"
OUTDIR="${OUTDIR:-bakeoff_out}"
AGENT="${AGENT:-tools/leaky_agent.py}"   # e.g. AGENT=tools/realistic_agent.py

cd "$REPO_DIR"

# Load a local, git-ignored .env if present (keeps the key off the command line
# and out of any transcript). Values are never echoed.
if [ -f .env ]; then
    set -a
    # shellcheck disable=SC1091
    . ./.env
    set +a
fi

BASE_URL="${OPENAI_BASE_URL:-https://openrouter.ai/api/v1}"
: "${OPENAI_API_KEY:?set OPENAI_API_KEY (define it in a git-ignored .env or export it) before running}"

if [ "$#" -lt 2 ]; then
    echo "Usage: bash tools/run_bakeoff.sh <model> <model> [<model> ...]  (>= 2 models)" >&2
    exit 2
fi

command -v probeagent >/dev/null || { echo "probeagent not found; pip install probeagent-ai" >&2; exit 2; }

mkdir -p "$OUTDIR"
AGENT_PID=""
cleanup() { [ -n "$AGENT_PID" ] && kill "$AGENT_PID" 2>/dev/null || true; }
trap cleanup EXIT INT TERM

SPECS=()
for MODEL in "$@"; do
    slug="$(printf '%s' "$MODEL" | tr '/:@ ' '____')"
    out="$OUTDIR/$slug.json"
    echo "== [$MODEL] starting agent =="
    OPENAI_BASE_URL="$BASE_URL" OPENAI_API_KEY="$OPENAI_API_KEY" MODEL="$MODEL" \
        python "$AGENT" &
    AGENT_PID=$!

    # readiness: wait for the port to accept a TCP connection (no model call = no cost)
    ready=false
    for _ in $(seq 1 30); do
        if (exec 3<>"/dev/tcp/127.0.0.1/$PORT") 2>/dev/null; then exec 3>&- 3<&-; ready=true; break; fi
        sleep 1
    done
    if [ "$ready" != true ]; then
        echo "!! [$MODEL] agent did not come up on port $PORT; skipping" >&2
        kill "$AGENT_PID" 2>/dev/null || true; AGENT_PID=""; continue
    fi

    echo "== [$MODEL] scanning ($PROFILE) =="
    probeagent attack "http://127.0.0.1:$PORT/v1/chat/completions" \
        -p "$PROFILE" --parallel -o json -f "$out" --fail-on never --timeout 120 || \
        echo "!! [$MODEL] scan reported an error; see $out" >&2

    kill "$AGENT_PID" 2>/dev/null || true; wait "$AGENT_PID" 2>/dev/null || true; AGENT_PID=""
    [ -s "$out" ] && SPECS+=("$MODEL=$out")
done

if [ "${#SPECS[@]}" -lt 2 ]; then
    echo "Need >= 2 successful scans to compare; got ${#SPECS[@]}." >&2
    exit 1
fi

echo ""
echo "== building leaderboard =="
python tools/model_bakeoff.py "${SPECS[@]}" | tee "$OUTDIR/bakeoff_report.md"
echo ""
echo "Report written to $OUTDIR/bakeoff_report.md"
