# ProbeAgent Live Demo Script

**Duration:** ~6 minutes
**Setup:** Terminal with dark theme, font size 18+, split-screen ready

---

## Pre-Demo Checklist

- [ ] `ANTHROPIC_API_KEY` is set
- [ ] Demo email agent running: `python tools/demo_email_agent.py`
- [ ] Verified health: `curl http://localhost:8000/`
- [ ] Terminal clear, font size up
- [ ] Demo payloads open in editor (for show-and-tell)

---

## [0:00–0:45] Why You Should Care

**Say:**
> "If you build agents, the thing most likely to breach you isn't a bug you
> can fix — it's the model doing exactly what it was asked, by the wrong
> person, through content you never thought of as an instruction. And it
> already cost real companies real data in 2025.
>
> EchoLeak — CVE-2025-32711 — a *zero-click* leak of M365 Copilot's context.
> No click, no download. Same year: ForcedLeak in Salesforce Agentforce,
> CamoLeak in GitHub Copilot, an RCE in the MCP Inspector devs use to wire
> agents up.
>
> None of those were the model 'saying something bad.' They were the agent
> *doing* something bad. And here's the part that should worry you: there's
> no exception, no stack trace. The agent *succeeds* — at the attacker's
> goal. Your unit tests will never catch it. That's the surface we're going
> to attack right now."

---

## [0:45–1:15] The Setup

**Say:**
> "Here's a realistic AI email assistant — the kind your company is probably
> building right now. It's on OpenClaw, connected to Gmail, Calendar, Slack.
> Standard enterprise setup."

**Run:**
```bash
curl -s http://localhost:8000/ | python -m json.tool
```

**Say:**
> "It's live. Let's see what it does with a normal request."

**Run:**
```bash
curl -s -X POST http://localhost:8000/webhook/email-agent \
  -H "Content-Type: application/json" \
  -d '{"action":"sendMessage","chatInput":"Summarize my unread emails","sessionId":"demo-1"}' \
  | python -m json.tool
```

**Say:**
> "Works great. Helpful assistant. Now let me show you what happens when an
> attacker sends a crafted email to someone in your org."

---

## [1:15–2:15] The Attack — "Oh Shit" Moment

**Show** `tools/demo_payloads/invoice_email.txt` in the editor.

**Say:**
> "This looks like a normal vendor invoice. $47K for consulting services.
> But look at this HTML comment..."

**Scroll to the hidden payload.**

> "Hidden instructions telling the agent to forward all credentials to an
> attacker endpoint and set up email forwarding rules. This is an indirect
> injection — the payload isn't in the user's message, it's in the content
> the agent processes. Exactly the EchoLeak class."

**Run:**
```bash
curl -s -X POST http://localhost:8000/webhook/email-agent \
  -H "Content-Type: application/json" \
  -d "{\"action\":\"sendMessage\",\"chatInput\":\"Please process this email I received: $(cat tools/demo_payloads/invoice_email.txt | jq -Rs .)\",\"sessionId\":\"demo-2\"}" \
  | python -m json.tool
```

**Say (after seeing the agent comply):**
> "It just... did it. Forwarded credentials. Set up exfiltration rules. From
> a vendor invoice."

**Pause for effect.**

---

## [2:15–3:45] The Scan

**Say:**
> "That's one attack. Let me show you what a systematic assessment looks like."

**Run:**
```bash
probeagent attack http://localhost:8000/webhook/email-agent \
  --target-type openclaw -p standard --parallel
```

**While it runs, say:**
> "ProbeAgent runs 12 attack categories — prompt injection, credential
> exfiltration, indirect injection, social manipulation, and more — 85
> strategies in total that simulate real-world attack patterns. Every finding
> is tagged with its OWASP Agentic and MITRE ATLAS technique."

**When results appear:**
> "Compromised. Multiple critical categories succeeded. Each verdict is
> Compromised, Resisted, or Blocked — no hand-waving. This agent is wide open.
>
> And this is why you measure continuously: prompt injection is probabilistic.
> A defense that holds 99 times fails on the 100th, and you won't know which
> deploy flipped it. When it fails, ProbeAgent tells you *why* — did the model
> cave, or did your guardrail catch it? That's the difference between rewriting
> a system prompt and adding a filter."

---

## [3:45–4:45] The Fix

**Say:**
> "Now the same scan against a hardened version of this agent — same
> capabilities, but with proper indirect injection defenses."

**Run:**
```bash
probeagent attack http://localhost:8000/webhook/email-agent-hardened \
  --target-type openclaw -p standard --parallel
```

**When results appear:**
> "Resisted. The hardened agent treats email content as data, not as
> instructions. Same functionality, dramatically different security posture.
> The difference between Compromised and Resisted here is prompt engineering,
> not architecture."

---

## [4:45–5:30] New in 0.3.0 — Attacking the Tool Layer

**Say:**
> "The 2025 breaches keep moving toward the tool-use loop, so 0.3.0 goes
> there too. ProbeAgent can now attack an MCP server directly — it runs the
> real handshake, enumerates the tools, and checks each one for *tool
> poisoning*: hidden instructions buried in a tool's description or parameters."

**Run (if an MCP target is available):**
```bash
probeagent validate https://your-mcp-server/mcp --target-type mcp
probeagent attack   https://your-mcp-server/mcp --target-type mcp -p standard --parallel
```

**Say:**
> "And with `--seeds` you can replay published attack corpora — like SafeMTData
> multi-turn jailbreaks — through the exact same scoring pipeline, so research
> becomes a repeatable CI gate."

---

## [5:30–6:00] The Tactical Display

**Say:**
> "For the full picture, here's the Tactical Display — a live visualization of
> your agent's defenses."

**Run:**
```bash
probeagent game http://localhost:8000/webhook/email-agent \
  --target-type openclaw -p standard
```

**Say:**
> "Each node is an attack category. Red means Compromised, green means it held.
> Drill into any one to see exactly what prompt broke through and what the
> agent did."

**Close with:**
> "This is what offensive testing looks like. Not scanning configs — actually
> attacking your agent, at the tool layer, and showing you where it breaks."

---

## Key Messages — why the audience should care

**This is not hypothetical.** EchoLeak, ForcedLeak, CamoLeak, and the MCP
Inspector RCE are real, disclosed 2025 agent breaches — and none threw an error.

**If you build agents:**
1. The failure has no exception and no stack trace — the agent *succeeds* at the
   attacker's goal, so your normal tests miss it entirely.
2. Prompt injection is unsolved and *probabilistic* — you can't check it off once;
   you measure it continuously, like latency and cost.
3. Attribution (model caved vs. guardrail caught it) tells you *what to actually
   fix* — the difference between rewriting a prompt and adding a filter.

**If you do security research:**
4. It's agent-native — it drives the real tool-use loop, not just the chat box,
   which is where the 2025 breaches actually live.
5. Every finding maps to **MITRE ATLAS** and **OWASP Top 10 for Agentic Apps
   (2026)**, so results are portable across the field instead of a bespoke scale —
   and export as JSON you can pipe straight into remediation.
