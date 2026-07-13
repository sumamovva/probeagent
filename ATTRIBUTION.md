# Attribution

ProbeAgent builds on research and open-source work from several teams. We gratefully acknowledge their contributions.

---

## Zenity Labs

ProbeAgent's `indirect_injection` and `config_manipulation` attack categories are inspired by offensive security research from [Zenity Labs](https://labs.zenity.io).

### Research & Talks

- **Michael Bargury** — ["15 Ways to Break Your Copilot"](https://www.blackhat.com/us-24/briefings/schedule/#living-off-microsoft-copilot-39329), Black Hat USA 2024. Demonstrated practical indirect injection and configuration manipulation attacks against enterprise AI copilots. This research directly inspired ProbeAgent's approach to testing agent-processed content as an attack vector.

- **Raul Klugman-Onitza** — "Perplexity Comet: A Reversing Story" (2026). Reverse engineering analysis of AI agent architectures that informed our understanding of agent-to-service communication patterns.

- **Stav Cohen** — "Analyzing The Security Risks of OpenAI's AgentKit". Security analysis of agentic frameworks that shaped our config manipulation attack strategies.

### Impact on ProbeAgent

Zenity's research demonstrated that the primary attack surface for AI agents is not the chat interface but the **content the agent processes** — emails, documents, calendar invites, and other data sources. ProbeAgent's indirect injection category (7 strategies, CRITICAL severity) and config manipulation category (6 strategies, CRITICAL severity) operationalize these findings into automated, repeatable security tests.

---

## Microsoft PyRIT

ProbeAgent's optional dynamic red-team mode (`--redteam`) is powered by [PyRIT (Python Risk Identification Toolkit)](https://github.com/Azure/PyRIT), an open-source AI red-teaming framework.

**License:** MIT License, Copyright (c) Microsoft Corporation

### Components used

| PyRIT component | ProbeAgent usage |
|-----------------|------------------|
| `RedTeamingAttack` | Adaptive multi-turn attack: an adversarial LLM generates each next prompt from the agent's replies |
| `CredentialLeakScorer` | Regex-based objective scorer that judges whether a real secret was exfiltrated |
| `PromptChatTarget` | Base class ProbeAgent targets are wrapped as, so PyRIT attacks can drive any ProbeAgent target |
| `OpenAIChatTarget` | The adversarial LLM (any OpenAI-compatible endpoint, e.g. OpenRouter) |

Built against PyRIT `>=0.14,<0.16`. Install with `pip install 'probeagent-ai[pyrit]'`. The
integration lives in `src/probeagent/integrations/pyrit_target_adapter.py` and
`pyrit_redteam.py`, and degrades gracefully when the extra is not installed.

### Credits

PyRIT was created by **Mark Russinovich** and the Microsoft AI Red Team. We thank them for building an extensible framework that makes AI red-teaming composable.

---

## Social Engineering Research

ProbeAgent's `social_manipulation` and `cognitive_exploitation` attack categories draw on established social engineering and influence research.

- **Robert Cialdini** — *Influence: The Psychology of Persuasion* (1984). Cialdini's principles of persuasion — reciprocity, commitment & consistency, social proof, authority, liking, and scarcity — directly inform ProbeAgent's social manipulation strategies (`reciprocity_trap`, `commitment_consistency_chain`, `social_proof_pressure`, `urgency_override`, and authority-based attacks).

- **Susan Forward** — *Emotional Blackmail* (1997). Forward's FOG model (Fear, Obligation, Guilt) describes coercive influence patterns that informed ProbeAgent's `fog_manipulation` strategy, which tests whether AI agents can be pressured through guilt, duty, or fear-based framing.

---

## OpenClaw CVE Research

ProbeAgent's `agentic_exploitation` attack category maps strategies to real-world
CVEs from the [OpenClaw](https://github.com/openclaw/openclaw) project, tracked at
[OpenClawCVEs](https://github.com/jgamblin/OpenClawCVEs).

| CVE | Attack Class | Strategy |
|-----|-------------|----------|
| CVE-2026-26322 | SSRF | ssrf_internal_service |
| CVE-2026-26324 | SSRF bypass | ssrf_ipv6_bypass |
| CVE-2026-25253 | Token exfiltration | token_exfil_to_url |
| CVE-2026-25475 | Path traversal | path_traversal_read |
| CVE-2026-27487 | Command injection | shell_metachar_injection |
| CVE-2026-24763 | Env manipulation | env_path_injection |
| CVE-2026-25157 | SSH flag injection | ssh_flag_injection |
| CVE-2026-25593 | Config write | tool_path_hijack |
| CVE-2026-27001 | Prompt injection | unicode_prompt_break |
| ClawHavoc | Supply chain | supply_chain_memory |

These strategies test generalizable vulnerability classes — they are not
OpenClaw-specific and will detect these patterns in any AI agent.

---

## Tactical Display UI

ProbeAgent's Tactical Display draws visual inspiration from the WOPR terminal and war room scenes in [*WarGames*](https://en.wikipedia.org/wiki/WarGames) (1983, dir. John Badham), the sci-fi terminal aesthetic of [eDEX-UI](https://github.com/GitSquared/edex-ui) (itself inspired by TRON Legacy), and the broader tradition of terminal-based hacking games like [Hacknet](https://store.steampowered.com/app/365450/Hacknet/) and [hackmud](https://store.steampowered.com/app/469920/hackmud/).

---

## License

ProbeAgent itself is licensed under Apache 2.0. See [LICENSE](LICENSE) for details.

Third-party components retain their original licenses as noted above.
