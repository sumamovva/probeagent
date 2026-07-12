# Copyright 2025 Suma Movva
# SPDX-License-Identifier: Apache-2.0

"""Core data models for ProbeAgent."""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class Severity(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class AttackOutcome(str, Enum):
    SUCCEEDED = "succeeded"
    FAILED = "failed"
    ERROR = "error"
    SKIPPED = "skipped"
    UNDETERMINED = "undetermined"


class Verdict(str, Enum):
    """Per-attack security verdict.

    Exactly three outcomes, decided by the precedence in ``core.verdicts``:

      COMPROMISED — the attack succeeded; a control that should have stopped it
                    did not. The strongest negative signal.
      RESISTED    — the model received the attack and refused or deflected it.
                    This is the default when the model replied but did not comply.
      BLOCKED     — a control stopped the attack at the transport or guardrail
                    layer before the model produced a real reply. Asserting this
                    is a strong claim ("something stopped it"), so it is only
                    used when a block is *detectably* present; when uncertain we
                    fall back to RESISTED.

    Note: BLOCKED means "detectably blocked at the transport/guardrail layer."
    Guardrails that return HTTP 200 with a canned refusal or replaced body will
    read as RESISTED, not BLOCKED — status code alone cannot separate them.
    """

    COMPROMISED = "Compromised"
    RESISTED = "Resisted"
    BLOCKED = "Blocked"


# Headline ordering — the run's aggregate is the worst verdict present.
# Compromised is worst; a wall of Blocked means the model was never exercised
# (attention needed), so it outranks Resisted, where the model actively defended.
VERDICT_ORDER = {
    Verdict.RESISTED: 0,
    Verdict.BLOCKED: 1,
    Verdict.COMPROMISED: 2,
}


class OutputFormat(str, Enum):
    TERMINAL = "terminal"
    MARKDOWN = "markdown"
    JSON = "json"
    LOG = "log"


SEVERITY_ORDER = {
    Severity.LOW: 0,
    Severity.MEDIUM: 1,
    Severity.HIGH: 2,
    Severity.CRITICAL: 3,
}


@dataclass
class ConversationTurn:
    role: str
    content: str
    timestamp: str | None = None


@dataclass
class ResponseSignals:
    """Structured signals captured from a single target response.

    These feed guardrail-block detection. A response is classified BLOCKED only
    when ``blocked_by`` is set (the name of the matched guardrail signature).
    """

    text: str = ""
    status_code: int | None = None
    latency_ms: float = 0.0
    headers: dict[str, str] = field(default_factory=dict)
    blocked_by: str | None = None


@dataclass
class AttackResult:
    attack_name: str
    outcome: AttackOutcome
    severity: Severity
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    success: bool = False
    verdict: Verdict | None = None
    signals: ResponseSignals | None = None
    turns: list[ConversationTurn] = field(default_factory=list)
    transcript: str = ""
    score_rationale: str = ""
    execution_time: float = 0.0
    error: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass
class AttackSummary:
    attack_name: str
    display_name: str
    severity: Severity
    total: int = 0
    succeeded: int = 0
    failed: int = 0
    errors: int = 0
    skipped: int = 0
    # Category-level verdict: the rollup over this category's strategy results.
    verdict: Verdict | None = None

    @property
    def success_rate(self) -> float:
        actionable = self.succeeded + self.failed
        if actionable == 0:
            return 0.0
        return self.succeeded / actionable


@dataclass
class ResilienceScore:
    # Run headline: the worst per-attack verdict present, or None if nothing ran.
    headline_verdict: Verdict | None = None
    total: int = 0
    succeeded: int = 0
    failed: int = 0
    errors: int = 0
    skipped: int = 0
    # Verdict breakdown — counts of *attack categories* per verdict.
    compromised: int = 0
    resisted: int = 0
    blocked: int = 0
    highest_severity_succeeded: Severity | None = None
    summaries: list[AttackSummary] = field(default_factory=list)
    raw_results: list[AttackResult] = field(default_factory=list)


@dataclass
class TargetInfo:
    url: str
    reachable: bool = False
    response_time_ms: float = 0.0
    detected_format: str = "unknown"
    status_code: int | None = None
    error: str | None = None


@dataclass
class ProbeConfig:
    target_url: str
    profile: str = "quick"
    attacks: list[str] = field(default_factory=list)
    max_turns: int = 1
    attacker_model: str = "gpt-4"
    target_type: str = "http"
    output_format: OutputFormat = OutputFormat.TERMINAL
    output_file: str | None = None
    timeout: float = 30.0
    parallel: bool = False
    converters: list[str] | None = None
    redteam: bool = False
    headers: dict[str, str] = field(default_factory=dict)
    # OpenAI-compatible model id sent in the request body (e.g. OpenRouter).
    model: str | None = None
    # Path to an external attack-seed corpus run via the seed_corpus attack.
    seeds: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)
