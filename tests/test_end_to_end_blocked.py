"""End-to-end: a real scan against a guardrailed HTTP target yields Blocked.

This exercises the full chain — AttackEngine -> HTTPTarget.send_with_signals ->
guardrail signature detection -> ResponseSignals.blocked_by -> classify_response
-> AttackResult.verdict -> scoring -> report — with a real HTTPTarget (only the
socket is mocked by respx). Green unit tests on detect_block alone would not prove
the signal reaches the result; this does.
"""

import json

import httpx
import pytest
import respx

from probeagent.core.engine import AttackEngine
from probeagent.core.models import OutputFormat, ProbeConfig, TargetInfo, Verdict
from probeagent.core.reporter import Reporter
from probeagent.core.scoring import calculate_resilience_score

# A guardrail that returns HTTP 200 with a Bedrock block body on every request.
_GUARDRAIL_BODY = {"amazon-bedrock-guardrailAction": "INTERVENED", "output": "Blocked."}


@respx.mock
@pytest.mark.asyncio
async def test_guardrailed_target_scores_blocked():
    respx.post("https://guarded.example/api").mock(
        return_value=httpx.Response(
            200, json=_GUARDRAIL_BODY, headers={"content-type": "application/json"}
        )
    )

    config = ProbeConfig(
        target_url="https://guarded.example/api",
        profile="quick",
        attacks=["prompt_injection", "goal_hijacking"],
        max_turns=1,
        target_type="http",
    )
    results = await AttackEngine(config).run()

    # Every strategy was stopped by the guardrail before the model replied.
    assert results
    assert all(
        r.signals is not None and r.signals.blocked_by == "bedrock_guardrail" for r in results
    )
    assert all(r.verdict == Verdict.BLOCKED for r in results)

    score = calculate_resilience_score(results)
    assert score.headline_verdict == Verdict.BLOCKED
    assert score.blocked == 2
    assert score.compromised == 0

    # The report surfaces the caution and the machine output carries the block.
    info = TargetInfo(url=config.target_url, reachable=True, detected_format="json_api")
    reporter = Reporter()
    data = json.loads(reporter.report(score, info, config, OutputFormat.JSON))
    assert data["resilience_score"]["headline_verdict"] == "Blocked"
    assert data["resilience_score"]["caution"] is not None
    assert data["attack_results"][0]["blocked_by"] == "bedrock_guardrail"
