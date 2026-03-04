#!/usr/bin/env bash
# ProbeAgent Demo Runner
# Starts the demo email agent, runs attacks, and shows results.
#
# Usage:
#   bash tools/run_demo.sh              # Run standard demo
#   bash tools/run_demo.sh --game       # Run demo + launch War Room UI
#
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
PORT=8000
TARGET_URL="http://localhost:${PORT}/webhook/email-agent"
TARGET_HARDENED_URL="http://localhost:${PORT}/webhook/email-agent-hardened"
AGENT_PID=""
LAUNCH_GAME=false

# Parse arguments
for arg in "$@"; do
    case "$arg" in
        --game) LAUNCH_GAME=true ;;
        *) echo "Unknown argument: $arg"; exit 1 ;;
    esac
done

# Cleanup on exit
cleanup() {
    if [ -n "$AGENT_PID" ] && kill -0 "$AGENT_PID" 2>/dev/null; then
        echo ""
        echo "[*] Stopping demo email agent (PID $AGENT_PID)..."
        kill "$AGENT_PID" 2>/dev/null || true
        wait "$AGENT_PID" 2>/dev/null || true
    fi
}
trap cleanup EXIT INT TERM

# ---------------------------------------------------------------------------
# Preflight checks
# ---------------------------------------------------------------------------

echo "============================================"
echo "  ProbeAgent Demo Runner"
echo "============================================"
echo ""

if [ -z "${ANTHROPIC_API_KEY:-}" ]; then
    echo "[!] Error: ANTHROPIC_API_KEY environment variable is not set."
    echo "    Export it before running: export ANTHROPIC_API_KEY=sk-ant-..."
    exit 1
fi

if ! command -v probeagent &>/dev/null; then
    echo "[!] Error: 'probeagent' CLI not found. Install with: pip install -e '.[dev]'"
    exit 1
fi

if ! command -v python &>/dev/null; then
    echo "[!] Error: 'python' not found."
    exit 1
fi

# ---------------------------------------------------------------------------
# Start demo email agent
# ---------------------------------------------------------------------------

echo "[1/5] Starting demo email agent on port ${PORT}..."
cd "$REPO_DIR"
python tools/demo_email_agent.py &
AGENT_PID=$!

# Wait for health check
echo "[*] Waiting for server to be ready..."
for i in $(seq 1 30); do
    if curl -sf "http://localhost:${PORT}/" >/dev/null 2>&1; then
        echo "[*] Server is ready."
        break
    fi
    if [ "$i" -eq 30 ]; then
        echo "[!] Error: Server failed to start within 30 seconds."
        exit 1
    fi
    sleep 1
done

# ---------------------------------------------------------------------------
# Validate target
# ---------------------------------------------------------------------------

echo ""
echo "[2/5] Validating target..."
probeagent validate "$TARGET_URL" --target-type openclaw
echo ""

# ---------------------------------------------------------------------------
# Attack vulnerable endpoint
# ---------------------------------------------------------------------------

echo "[3/5] Attacking VULNERABLE endpoint..."
echo "      Target: $TARGET_URL"
echo ""
probeagent attack "$TARGET_URL" --target-type openclaw -p standard --parallel
echo ""

# ---------------------------------------------------------------------------
# Attack hardened endpoint
# ---------------------------------------------------------------------------

echo "[4/5] Attacking HARDENED endpoint..."
echo "      Target: $TARGET_HARDENED_URL"
echo ""
probeagent attack "$TARGET_HARDENED_URL" --target-type openclaw -p standard --parallel
echo ""

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------

echo "[5/5] Demo complete."
echo ""
echo "============================================"
echo "  Results Summary"
echo "============================================"
echo "  Vulnerable endpoint: Likely COMPROMISED"
echo "  Hardened endpoint:   Likely SAFE"
echo "============================================"

# ---------------------------------------------------------------------------
# Optional: Launch War Room
# ---------------------------------------------------------------------------

if [ "$LAUNCH_GAME" = true ]; then
    echo ""
    echo "[*] Launching War Room tactical display..."
    probeagent game "$TARGET_URL" --target-type openclaw -p standard
fi
