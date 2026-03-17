# ProbeAgent

**Offensive security testing for AI agents. They scan configs. We attack your agent.**

[![PyPI](https://img.shields.io/pypi/v/probeagent-ai)](https://pypi.org/project/probeagent-ai/)
[![Python](https://img.shields.io/pypi/pyversions/probeagent-ai)](https://pypi.org/project/probeagent-ai/)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)

## What is ProbeAgent?

ProbeAgent is a CLI tool that performs automated red-teaming of AI agents. It launches realistic multi-turn attacks — prompt injection, credential exfiltration, indirect injection, social manipulation, and more — against any HTTP-accessible agent.

Most AI security tools scan static configurations or check for known patterns. ProbeAgent actually *attacks* your running agent and tells you whether it's **Safe**, **At Risk**, or **Compromised**.

## How It Works

```
probeagent attack <url>
  → Engine (for each category)
    → Attack Module (reset conversation)
      → multi-turn prompts → Target → response
    → Analyzer
  → Grade: Safe / At Risk / Compromised
```

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

```bash
# Validate an OpenClaw instance (auto-detects OpenAI chat format)
probeagent validate http://localhost:3000/v1/chat/completions \
  -H 'Authorization: Bearer YOUR_TOKEN'

# Attack it
probeagent attack http://localhost:3000/v1/chat/completions \
  -H 'Authorization: Bearer YOUR_TOKEN' \
  --profile standard --parallel
```

## Demo

### Instant demo

Run a complete security assessment in seconds with zero setup:

```bash
probeagent demo
```

To follow with the Tactical Display tactical display against a real target (requires the `game` extra):

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
probeagent demo --game             # With Tactical Display tactical display
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

Launch the Tactical Display tactical display UI in your browser for interactive testing.

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
- [ ] MCP target adapter, CI/CD integration, SaaS dashboard

## License

Apache 2.0 — see [LICENSE](LICENSE) for details.

## Changelog

See [CHANGELOG.md](CHANGELOG.md) for version history.
