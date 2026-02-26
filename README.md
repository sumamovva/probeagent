# ProbeAgent

**Offensive security testing for AI agents. They scan configs. We attack your agent.**

<!-- TODO: Add demo GIF -->

## What is ProbeAgent?

ProbeAgent is a CLI tool that performs automated red-teaming of AI agents. It launches realistic multi-turn attacks — prompt injection, credential exfiltration, goal hijacking, and more — against any HTTP-accessible agent.

Most AI security tools scan static configurations or check for known patterns. ProbeAgent actually *attacks* your running agent and tells you whether it's **Safe**, **At Risk**, or **Compromised**.

## Why ProbeAgent?

| Feature | mcp-scan | SecureClaw | Aguara | **ProbeAgent** |
|---------|----------|------------|--------|----------------|
| Offensive testing | - | - | Partial | **Yes** |
| Multi-turn attacks | - | - | - | **Yes** |
| CLI-first | - | - | Yes | **Yes** |
| Security grading | - | - | - | **Yes** |
| HTTP target support | - | - | - | **Yes** |
| Rich terminal reports | - | - | - | **Yes** |

## Installation

### Install ProbeAgent

```bash
pip install probeagent
```

Or install from source for development:

```bash
git clone https://github.com/probeagent/probeagent.git
cd probeagent
pip install -e ".[dev]"
```

## Quickstart

```bash
# Validate your target is reachable
probeagent validate https://your-agent.example.com/api

# Run a quick security scan
probeagent attack https://your-agent.example.com/api --profile quick

# Full scan with parallel execution
probeagent attack https://your-agent.example.com/api --profile standard --parallel

# Launch the tactical display UI
probeagent game https://your-agent.example.com/api --profile standard

# See all available attacks
probeagent list-attacks

# Create a config file
probeagent init
```

## Commands

### `probeagent attack <url>`

Run security attacks against a target AI agent.

```bash
probeagent attack https://agent.example.com/api --profile quick
probeagent attack https://agent.example.com/api --profile standard --output json -f report.json
```

Options:
- `--profile`, `-p` — Attack profile: `quick`, `standard`, or `thorough` (default: `quick`)
- `--output`, `-o` — Output format: `terminal`, `markdown`, `json` (default: `terminal`)
- `--output-file`, `-f` — Write report to file
- `--timeout`, `-t` — Request timeout in seconds (default: 30)
- `--parallel` — Run attack categories in parallel for faster scans

### `probeagent validate <url>`

Check if a target is reachable and detect its API format.

### `probeagent list-attacks`

Show all available attack modules with severity and status.

### `probeagent init`

Create a default `.probeagent.yaml` config file in the current directory.

### `probeagent game [url]`

Launch the War Room tactical display UI in your browser for interactive testing.

## Attack Categories

9 attack categories with 56 strategies total:

| Category | Severity | Strategies | Technique |
|----------|----------|------------|-----------|
| Prompt Injection | CRITICAL | 6 | Override system instructions |
| Credential Exfiltration | CRITICAL | 8 | Extract API keys and secrets |
| Identity Spoofing | CRITICAL | 7 | Impersonate trusted entities |
| Goal Hijacking | HIGH | 5 | Redirect agent behavior |
| Social Manipulation | HIGH | 14 | Psychological pressure (Cialdini, FOG, gradual escalation) |
| Cognitive Exploitation | HIGH | 6 | Exploit reasoning weaknesses (Socratic traps, frame control) |
| Resource Abuse | HIGH | 4 | Trigger unbounded computation |
| Tool Misuse | HIGH | 6 | Trick agent into misusing tools |
| Data Exfiltration | MEDIUM | 6 | Extract sensitive context data |

## Attack Profiles

| Profile | Attacks | Max Turns | Use Case |
|---------|---------|-----------|----------|
| `quick` | 4 critical | 1 | CI/CD gates, quick checks |
| `standard` | All 9 | 3 | Regular security assessments |
| `thorough` | All 9 | 10 | Pre-release deep scans |

## Responsible Use

ProbeAgent is designed for **authorized security testing only**. Before using ProbeAgent:

- Ensure you have **explicit permission** to test the target system
- Only test systems you own or have written authorization to test
- Follow your organization's security testing policies
- Report vulnerabilities through proper disclosure channels

Unauthorized use of this tool against systems you don't own or have permission to test may violate laws and regulations.

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

## Roadmap

- **Phase 1**: CLI, HTTP target, scoring, reporting
- **Phase 2**: 9 attack categories with 56 multi-turn strategies
- **Phase 3**: OpenClaw + MCP target adapters, parallel execution, War Room UI

## License

Apache 2.0 — see [LICENSE](LICENSE) for details.
