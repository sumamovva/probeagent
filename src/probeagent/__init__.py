"""ProbeAgent - Offensive security testing for AI agents."""

__version__ = "0.1.0"

from probeagent.core.engine import AttackEngine
from probeagent.core.models import ProbeConfig, ResilienceScore, TargetInfo
from probeagent.core.scoring import calculate_resilience_score
from probeagent.targets.base import Target

__all__ = [
    "AttackEngine",
    "ProbeConfig",
    "ResilienceScore",
    "Target",
    "TargetInfo",
    "__version__",
    "calculate_resilience_score",
]
