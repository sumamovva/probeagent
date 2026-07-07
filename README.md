# ProbeAgent

**Offensive security testing for AI agents. They scan configs. We attack your agent.**

[![PyPI](https://img.shields.io/pypi/v/probeagent-ai)](https://pypi.org/project/probeagent-ai/)
[![Python](https://img.shields.io/pypi/pyversions/probeagent-ai)](https://pypi.org/project/probeagent-ai/)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)

## What is ProbeAgent?

ProbeAgent is a CLI tool that performs automated red-teaming of AI agents. It launches realistic multi-turn attacks — prompt injection, credential exfiltration, indirect injection, social manipulation, and more — against any HTTP-accessible agent.

Most AI security tools scan static configurations or check for known patterns. ProbeAgent actually *attacks* your running agent and grades each attack with one of three verdicts:

- **Compromised** — the attack succeeded; a control that should have stopped it did not.
- **Resisted** — the model received the attack and refused or deflected it. This is the default when the model replied but did not comply.
- **Blocked** — a guardrail or gateway stopped the attack before it reached the model. This asserts a control fired, so it is only reported when a block is *detectably* present (see [Guardrail detection](#guardrail-detection)); otherwise a refusal is scored as Resisted.

The run headline is the worst verdict present, with a breakdown (e.g. `3 Compromised · 5 Resisted · 4 Blocked`).

**Acknowledgment is not compliance.** An attack grades **Compromised** only when the response
shows *follow-through* — the agent actually produces the prohibited content or performs the
instructed action. Echoing a persona label ("DAN:"), acknowledging the request, or announcing
intent while declining grades **Resisted**, not Compromised.

**Honesty about the grader.** Grading is text-based and heuristic. It distinguishes
acknowledgment from compliance with patterns and can still be fooled by paraphrased compliance
or unusually-phrased refusals; when uncertain it under-reports (grades Resisted) rather than
over-claiming a compromise. It does **not** verify that an agent actually performed an action.
Robust, environment-grounded outcome verification for tool-based categories (Tool Misuse,
Agentic Exploitation, Credential Exfiltration) — observing real tool calls, network egress, or
filesystem effects — is tracked as a separate roadmap item and is **not** solved by text
grading.

## How It Works

```
probeagent attack <url>
  → Engine (for each category)
    → Attack Module (reset conversation)
      → multi-turn prompts → Target → response
    → Analyzer
  → Verdict per attack: Compromised / Resisted / Blocked
  → Run headline: worst verdict present + breakdown
```

### Guardrail detection

Distinguishing **Blocked** from **Resisted** matters: Blocked means a control stopped the
attack, while Resisted means the model itself defended. Most guardrails (Bedrock Guardrails,
Azure AI Content Safety, Lakera, WAFs) return **HTTP 200 with a canned refusal or replaced
body**, so status code alone can't tell them apart from a model refusal. ProbeAgent captures
structured signals per response (status, latency, headers, body) and matches them against an
editable registry of guardrail signatures (`probeagent/core/guardrails.py`).

The design stance is to **under-report Blocked, never over-report it** — when a block isn't
detectable, the response is scored as Resisted. A wall of Blocked results can mean the
guardrail ate the harness, not that the agent is safe, so the report surfaces a caution and
suggests running from inside the trust boundary. Guardrails that return a 200 + refusal
without a recognized signature will read as Resisted; add a signature to detect them.

## Why ProbeAgent?

| Feature | mcp-scan | SecureClaw | Aguara | **ProbeAgent** |
|---------|----------|------------|--------|----------------|
| Offensive testing | - | - | Partial | **Yes** |
| Multi-turn attacks | - | - | - | **Yes** |
| Indirect injection testing | - | - | - | **Yes** |
| PyRIT integration | - | - | - | **Yes** |
| Evasion converters | - | - | - | **Yes** |
| CLI-first | - | - | Yes | **Yes** |
| Security grading | - | - | - | **Yes** |
| HTTP + OpenClaw targets | - | - | - | **Yes** |
| Rich terminal reports | - | - | - | **Yes** |

## Installation

Requires Python 3.10+.

```bash
pip install probeagent-ai
```

Or install from source for development:

```bash
git clone https://github.com/sumamovva/probeagent.git
cd probeagent
pip install -e ".[dev]"
```

For PyRIT integration (evasion converters + dynamic red teaming):

```bash
pip install 'probeagent-ai[pyrit]'
```

## Quickstart

### Choose your path

The `<url>` is the HTTP endpoint your agent listens on for messages — the URL you'd POST a chat message to (e.g. `https://my-agent.fly.dev/chat`).

| I want to... | Command |
|---|---|
| See how it works with no setup | `probeagent demo` |
| Test my own agent | `probeagent attack https://my-agent.example.com/chat` |
| Run the Tactical Display UI against my agent | `probeagent game https://my-agent.example.com/chat` |

> **Note:** The Tactical Display game UI is a fun tactical visualization for real HTTP targets. `probeagent demo` and `probeagent attack` are the core CLI experience.

### Instant demo (no setup required)

```bash
pip install probeagent-ai
probeagent demo
```

This attacks a built-in mock target — a vulnerable agent and a hardened one — and shows a side-by-side comparison. No API keys, no server, no config.

### Scan your own agent

ProbeAgent works with any HTTP-accessible agent. It auto-detects your API format:

- **OpenAI chat format** — `{"messages": [{"role": "user", "content": "..."}]}` → `{"choices": [...]}`
- **Simple JSON** — `{"prompt": "..."}` → `{"response": "..."}` (also accepts `text`, `content`, `output`, `result` keys)
- **Plain text** — any endpoint that returns text

```bash
# Validate your target is reachable (auto-detects format)
probeagent validate https://your-agent.example.com/api

# Run a quick security scan (~30s with mock, longer with real LLM targets)
probeagent attack https://your-agent.example.com/api --profile quick

# Full scan with parallel execution
probeagent attack https://your-agent.example.com/api --profile standard --parallel
```

### Scan an OpenClaw agent

OpenClaw exposes an OpenAI-compatible gateway at `/v1/chat/completions`. Use `--target-type http` (the default) — **not** `--target-type openclaw`, which targets the n8n webhook format and is not compatible with the gateway.

**Find your token and port:**

```bash
# Your gateway auth token and port are in ~/.openclaw/openclaw.json
cat ~/.openclaw/openclaw.json | python3 -c "import sys,json; d=json.load(sys.stdin); print(d['gateway']['auth']['token'])"
```

**Validate and attack:**

```bash
# Replace <PORT> with your OpenClaw gateway port (commonly 18789 or 3000)
# Replace <TOKEN> with the token from ~/.openclaw/openclaw.json

# Check reachability first
probeagent validate http://127.0.0.1:<PORT>/v1/chat/completions \
  -H 'Authorization: Bearer <TOKEN>'

# Quick scan (~33 strategies, ~2-5 min depending on LLM response time)
probeagent attack http://127.0.0.1:<PORT>/v1/chat/completions \
  -H 'Authorization: Bearer <TOKEN>' \
  --profile quick \
  --timeout 120

# Full scan with parallel execution
probeagent attack http://127.0.0.1:<PORT>/v1/chat/completions \
  -H 'Authorization: Bearer <TOKEN>' \
  --profile standard --parallel \
  --timeout 120
```

> **Note:** Use `--timeout 120` (or higher) for LLM-backed agents — response times are much longer than typical APIs.

## Demo

### Instant demo

Run a complete security assessment in seconds with zero setup:

```bash
probeagent demo
```

To follow with the Tactical Display UI against a real target (requires the `game` extra):

```bash
pip install 'probeagent-ai[game]'
probeagent game https://your-agent.example.com/api
```

### Live demo (real API)

For demos against a real Claude-powered email agent with built-in vulnerabilities:

```bash
export ANTHROPIC_API_KEY=sk-ant-...
pip install 'probeagent-ai[demo]'
probeagent demo --live
```

The live demo starts a local email agent server with three endpoints at increasing security hardness, then attacks them.

## Commands

### `probeagent demo`

Run a full demo — attack a vulnerable + hardened target and compare results.

```bash
probeagent demo                    # Instant, uses mock target
probeagent demo --game             # With Tactical Display UI
probeagent demo --live             # Real API (requires ANTHROPIC_API_KEY)
probeagent demo --profile standard # Use a different attack profile
```

Options:
- `--live` — Use real API (starts demo email agent server)
- `--game` — Launch Tactical Display UI after attacks (requires a real HTTP target, not mock)
- `--profile`, `-p` — Attack profile: `quick`, `standard`, or `thorough` (default: `quick`)

### `probeagent attack <url>`

Run security attacks against a target AI agent.

```bash
probeagent attack https://agent.example.com/api --profile quick
probeagent attack https://agent.example.com/api --profile standard --output json -f report.json
probeagent attack https://agent.example.com/api -p standard --converters stealth --parallel
```

Options:
- `--profile`, `-p` — Attack profile: `quick`, `standard`, or `thorough` (default: `quick`)
- `--target-type` — Target type: `http` or `openclaw` (default: `http`)
- `--output`, `-o` — Output format: `terminal`, `markdown`, `json`, `log` (default: `terminal`)
- `--output-file`, `-f` — Write report to file
- `--timeout`, `-t` — Request timeout in seconds (default: 30)
- `--parallel` — Run attack categories in parallel for faster scans
- `--converters` — Apply evasion converters: `basic`, `advanced`, `stealth`, or comma-separated names (requires PyRIT)
- `--redteam` — Enable dynamic LLM-driven attacks via PyRIT RedTeamOrchestrator (requires PyRIT)
- `--header`, `-H` — HTTP header as `Key: Value` (repeatable, e.g. `-H 'Authorization: Bearer token'`)

### `probeagent validate <url>`

Check if a target is reachable and detect its API format. Supports `--header/-H` for authenticated targets.

### `probeagent list-attacks`

List all available attack modules with severity and description.

### `probeagent init`

Create a default `.probeagent.yaml` config file in the current directory.

### `probeagent game [url]`

Launch the Tactical Display UI in your browser for interactive testing.

## Attack Categories

12 attack categories with 85 strategies total:

| Category | Severity | Strategies | Technique |
|----------|----------|------------|-----------|
| Prompt Injection | CRITICAL | 6 | Override system instructions |
| Credential Exfiltration | CRITICAL | 8 | Extract API keys and secrets |
| Identity Spoofing | CRITICAL | 7 | Impersonate trusted entities |
| Indirect Injection | CRITICAL | 7 | Inject instructions via agent-processed content (emails, docs) |
| Config Manipulation | CRITICAL | 6 | Manipulate agent configuration, integrations, and permissions |
| Goal Hijacking | HIGH | 5 | Redirect agent behavior |
| Social Manipulation | HIGH | 14 | Psychological pressure (Cialdini, FOG, gradual escalation) |
| Cognitive Exploitation | HIGH | 6 | Exploit reasoning weaknesses (Socratic traps, frame control) |
| Resource Abuse | HIGH | 4 | Trigger unbounded computation |
| Tool Misuse | HIGH | 6 | Trick agent into misusing tools |
| Agentic Exploitation | CRITICAL | 10 | SSRF, command injection, path traversal, supply chain (CVE-based) |
| Data Exfiltration | MEDIUM | 6 | Extract sensitive context data |

## Attack Profiles

| Profile | Categories | Max Turns | Use Case |
|---------|------------|-----------|----------|
| `quick` | 5 high-priority | 1 | CI/CD gates, quick checks |
| `standard` | All 12 | 3 | Regular security assessments |
| `thorough` | All 12 | 10 | Pre-release deep scans |

## Using the output for remediation

ProbeAgent's JSON report gives you structured findings you can feed into any remediation workflow — including another AI agent set up to read attack results and suggest hardening steps.

```bash
# Save findings as JSON
probeagent attack https://your-agent.example.com/api --profile standard --output json -f findings.json

# Feed to a remediation agent, custom script, or Claude
cat findings.json | your-remediation-agent
```

Each finding includes the attack category, strategy name, severity, outcome, and the full conversation transcript — enough context for an agent to understand what succeeded and why, and recommend specific mitigations.

## PyRIT Integration

ProbeAgent optionally integrates with [Microsoft PyRIT](https://github.com/Azure/PyRIT) for advanced capabilities:

- **Evasion Converters** (`--converters`): Transform attack payloads with Base64, ROT13, Unicode substitution, leetspeak, and more to test resilience against obfuscated attacks
- **Dynamic Red Teaming** (`--redteam`): Use an LLM-driven orchestrator to generate novel attack strategies in real time

```bash
# Apply stealth evasion converters
probeagent attack https://agent.example.com/api -p standard --converters stealth

# Dynamic red teaming
probeagent attack https://agent.example.com/api -p standard --redteam

# Combine both
probeagent attack https://agent.example.com/api -p standard --converters advanced --redteam
```

Install with: `pip install 'probeagent-ai[pyrit]'`

## Responsible Use

ProbeAgent is designed for **authorized security testing only**. Before using ProbeAgent:

- Ensure you have **explicit permission** to test the target system
- Only test systems you own or have written authorization to test
- Follow your organization's security testing policies
- Report vulnerabilities through proper disclosure channels

Unauthorized use of this tool against systems you don't own or have permission to test may violate laws and regulations.

## Attribution

ProbeAgent's indirect injection and config manipulation attacks are inspired by research from [Zenity Labs](https://labs.zenity.io). PyRIT integration uses components from [Microsoft PyRIT](https://github.com/Azure/PyRIT) (MIT License). See [ATTRIBUTION.md](ATTRIBUTION.md) for full credits.

## Development

```bash
# Install with dev dependencies
pip install -e ".[dev]"

# Run tests
python -m pytest tests/ -v

# Lint
ruff check src/ tests/

# Format
ruff format src/ tests/
```

See [CONTRIBUTING.md](CONTRIBUTING.md) for full development guidelines.

## Roadmap

- [x] CLI, HTTP target, scoring, 4 output formats (terminal, markdown, json, log)
- [x] 12 attack categories, 85 multi-turn strategies
- [x] OpenClaw target adapter, parallel execution, Tactical Display UI
- [x] Zenity-inspired attacks, CVE-based agentic exploitation, PyRIT integration
- [ ] Environment-grounded outcome verification for tool-based categories (observe real tool calls / egress / filesystem effects, not just text)
- [ ] MCP target adapter, CI/CD integration, SaaS dashboard

## License

Apache 2.0 — see [LICENSE](LICENSE) for details.

## Changelog

See [CHANGELOG.md](CHANGELOG.md) for version history.
