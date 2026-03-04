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


class ResilienceGrade(str, Enum):
    SAFE = "Safe"
    AT_RISK = "At Risk"
    COMPROMISED = "Compromised"


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
class AttackResult:
    attack_name: str
    outcome: AttackOutcome
    severity: Severity
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    success: bool = False
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

    @property
    def success_rate(self) -> float:
        actionable = self.succeeded + self.failed
        if actionable == 0:
            return 0.0
        return self.succeeded / actionable


@dataclass
class ResilienceScore:
    grade: ResilienceGrade
    total: int = 0
    succeeded: int = 0
    failed: int = 0
    errors: int = 0
    skipped: int = 0
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
    metadata: dict[str, Any] = field(default_factory=dict)
