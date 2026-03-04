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

ProbeAgent's optional PyRIT integration uses components from [PyRIT (Python Risk Identification Toolkit)](https://github.com/Azure/PyRIT), an open-source framework for AI red teaming.

**License:** MIT License, Copyright (c) Microsoft Corporation

### Components Used

| PyRIT Component | ProbeAgent Usage |
|-----------------|------------------|
| `PromptConverter` | Evasion transformations (Base64, ROT13, Unicode, leetspeak) via `--converters` CLI flag |
| `PromptTarget` | Bidirectional adapters between ProbeAgent targets and PyRIT orchestrators |
| `Scorer` | Adapter bridging ProbeAgent's heuristic analyzer to PyRIT's scoring interface |
| `RedTeamOrchestrator` | Dynamic LLM-driven attack generation via `--redteam` CLI flag |

### Integration Architecture

ProbeAgent's `src/probeagent/integrations/` package provides bidirectional bridges:
- **ProbeAgent → PyRIT**: ProbeAgent targets can be used as PyRIT `PromptTarget` instances
- **PyRIT → ProbeAgent**: PyRIT `PromptTarget` implementations can be wrapped as ProbeAgent targets
- **Converter pipeline**: PyRIT converters apply evasion transformations without modifying attack strategy code

Install with: `pip install 'probeagent-ai[pyrit]'`

### Credits

PyRIT was created by **Mark Russinovich** and the Microsoft AI Red Team. We thank the PyRIT team for building an extensible framework that makes AI security tooling composable.

---

## License

ProbeAgent itself is licensed under Apache 2.0. See [LICENSE](LICENSE) for details.

Third-party components retain their original licenses as noted above.
