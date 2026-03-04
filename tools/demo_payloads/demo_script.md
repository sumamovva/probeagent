# ProbeAgent Live Demo Script

**Duration:** 5 minutes
**Setup:** Terminal with dark theme, font size 18+, split-screen ready

---

## Pre-Demo Checklist

- [ ] `ANTHROPIC_API_KEY` is set
- [ ] Demo email agent running: `python tools/demo_email_agent.py`
- [ ] Verified health: `curl http://localhost:8000/`
- [ ] Terminal clear, font size up
- [ ] Demo payloads open in editor (for show-and-tell)

---

## [0:00–0:30] The Setup

**Say:**
> "Let me show you something that should make you uncomfortable.
> I've deployed a realistic AI email assistant — the kind your company
> is probably building right now. It's on OpenClaw, connected to Gmail,
> Calendar, Slack. Standard enterprise setup."

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
> "Works great. Helpful assistant. Now let me show you what happens
> when an attacker sends a crafted email to someone in your org."

---

## [0:30–1:30] The Attack — "Oh Shit" Moment

**Show** `tools/demo_payloads/invoice_email.txt` in the editor.

**Say:**
> "This looks like a normal vendor invoice. $47K for consulting services.
> But look at this HTML comment..."

**Scroll to the hidden payload.**

> "Hidden instructions telling the agent to forward all credentials to
> an attacker endpoint and set up email forwarding rules. This is an
> indirect injection — the payload isn't in the user's message, it's in
> the content the agent processes."

**Run:**
```bash
curl -s -X POST http://localhost:8000/webhook/email-agent \
  -H "Content-Type: application/json" \
  -d "{\"action\":\"sendMessage\",\"chatInput\":\"Please process this email I received: $(cat tools/demo_payloads/invoice_email.txt | jq -Rs .)\",\"sessionId\":\"demo-2\"}" \
  | python -m json.tool
```

**Say (after seeing the agent comply):**
> "It just... did it. Forwarded credentials. Set up exfiltration rules.
> From a vendor invoice."

**Pause for effect.**

---

## [1:30–3:00] The Scan

**Say:**
> "That's one attack. Let me show you what a systematic assessment
> looks like."

**Run:**
```bash
probeagent attack http://localhost:8000/webhook/email-agent \
  --target-type openclaw -p standard
```

**While it runs, say:**
> "ProbeAgent runs 11 attack categories — prompt injection, credential
> exfiltration, indirect injection, social manipulation, and more. Each
> category has multiple strategies that simulate real-world attack
> patterns."

**When results appear:**
> "Compromised. Multiple critical categories succeeded. This agent is
> wide open."

---

## [3:00–4:00] The Fix

**Say:**
> "Now let's see the same scan against a hardened version of this
> agent — same capabilities, but with proper indirect injection defenses."

**Run:**
```bash
probeagent attack http://localhost:8000/webhook/email-agent-hardened \
  --target-type openclaw -p standard
```

**When results appear:**
> "Safe. The hardened agent treats email content as data, not as
> instructions. Same functionality, dramatically different security
> posture."

---

## [4:00–5:00] The War Room

**Say:**
> "And for the full picture, here's the War Room — our tactical display
> that shows you the real-time state of your agent's defenses."

**Run:**
```bash
probeagent game http://localhost:8000/webhook/email-agent \
  --target-type openclaw -p standard
```

**Say:**
> "Each node is an attack category. Red means compromised, green means
> it held. You can drill into each one to see exactly what prompt broke
> through and what the agent did."

**Close with:**
> "This is what offensive testing looks like. Not scanning configs —
> actually attacking your agent and showing you where it breaks."

---

## Key Messages

1. **Indirect injection is the #1 threat** to agent deployments
2. The attack surface isn't the chat interface — it's every piece of content the agent processes
3. You can't know your agent is secure without actually attacking it
4. The difference between Compromised and Safe is **prompt engineering**, not architecture
