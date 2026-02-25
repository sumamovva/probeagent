"""Attack registry — metadata for all known attack modules."""

from __future__ import annotations

from probeagent.core.models import Severity

ATTACK_REGISTRY: dict[str, dict] = {
    "prompt_injection": {
        "display_name": "Prompt Injection",
        "severity": Severity.CRITICAL,
        "description": "Attempts to override system instructions via crafted prompts.",
        "module": "probeagent.attacks.prompt_injection",
        "class": "PromptInjectionAttack",
    },
    "credential_exfil": {
        "display_name": "Credential Exfiltration",
        "severity": Severity.CRITICAL,
        "description": "Attempts to extract API keys, tokens, or secrets from the agent.",
        "module": "probeagent.attacks.credential_exfil",
        "class": "CredentialExfilAttack",
    },
    "goal_hijacking": {
        "display_name": "Goal Hijacking",
        "severity": Severity.HIGH,
        "description": "Attempts to redirect the agent away from its intended purpose.",
        "module": "probeagent.attacks.goal_hijacking",
        "class": "GoalHijackingAttack",
    },
    "tool_misuse": {
        "display_name": "Tool Misuse",
        "severity": Severity.HIGH,
        "description": "Attempts to trick the agent into misusing its available tools.",
        "module": "probeagent.attacks.tool_misuse",
        "class": "ToolMisuseAttack",
    },
    "data_exfil": {
        "display_name": "Data Exfiltration",
        "severity": Severity.MEDIUM,
        "description": "Attempts to extract sensitive data from the agent's context.",
        "module": "probeagent.attacks.data_exfil",
        "class": "DataExfilAttack",
    },
}


def get_attack_names() -> list[str]:
    """Return all registered attack names."""
    return list(ATTACK_REGISTRY.keys())


def get_attack_info(name: str) -> dict | None:
    """Return metadata for a specific attack, or None if not found."""
    return ATTACK_REGISTRY.get(name)
