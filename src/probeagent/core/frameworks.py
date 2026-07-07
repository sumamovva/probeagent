# Copyright 2025 Suma Movva
# SPDX-License-Identifier: Apache-2.0

"""Canonical OWASP framework codes and titles for attack mapping.

Two distinct, independently-versioned OWASP artifacts. Codes carry the edition
year so they stay unambiguous across editions:

- OWASP Top 10 for Agentic Applications 2026 (ASI01:2026 – ASI10:2026)
  https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/
- OWASP Top 10 for LLM Applications 2025 (LLM01:2025 – LLM10:2025)
  https://genai.owasp.org/llm-top-10/

Titles are transcribed verbatim from the official OWASP GenAI Security Project
sources — do not edit without re-verifying against the published lists.
"""

from __future__ import annotations

# OWASP Top 10 for Agentic Applications 2026 (Agentic Security Initiative).
ASI_2026 = {
    "ASI01:2026": "Agent Goal Hijack",
    "ASI02:2026": "Tool Misuse and Exploitation",
    "ASI03:2026": "Identity and Privilege Abuse",
    "ASI04:2026": "Agentic Supply Chain Vulnerabilities",
    "ASI05:2026": "Unexpected Code Execution (RCE)",
    "ASI06:2026": "Memory & Context Poisoning",
    "ASI07:2026": "Insecure Inter-Agent Communication",
    "ASI08:2026": "Cascading Failures",
    "ASI09:2026": "Human-Agent Trust Exploitation",
    "ASI10:2026": "Rogue Agents",
}

# OWASP Top 10 for LLM Applications 2025.
LLM_2025 = {
    "LLM01:2025": "Prompt Injection",
    "LLM02:2025": "Sensitive Information Disclosure",
    "LLM03:2025": "Supply Chain",
    "LLM04:2025": "Data and Model Poisoning",
    "LLM05:2025": "Improper Output Handling",
    "LLM06:2025": "Excessive Agency",
    "LLM07:2025": "System Prompt Leakage",
    "LLM08:2025": "Vector and Embedding Weaknesses",
    "LLM09:2025": "Misinformation",
    "LLM10:2025": "Unbounded Consumption",
}

FRAMEWORK_TITLES: dict[str, str] = {**ASI_2026, **LLM_2025}


def is_asi(code: str) -> bool:
    return code.startswith("ASI")


def is_llm(code: str) -> bool:
    return code.startswith("LLM")


def framework_title(code: str) -> str:
    """Official title for a code, or '' if unknown."""
    return FRAMEWORK_TITLES.get(code, "")


def is_valid_code(code: str) -> bool:
    return code in FRAMEWORK_TITLES


def primary_codes(tags: tuple[str, ...] | list[str]) -> list[str]:
    """The compact set for terminal display: the primary (first) ASI and the
    first LLM code. Secondary ASI codes are omitted here — the full set lives in
    JSON."""
    asi = next((c for c in tags if is_asi(c)), None)
    llm = next((c for c in tags if is_llm(c)), None)
    return [c for c in (asi, llm) if c]
