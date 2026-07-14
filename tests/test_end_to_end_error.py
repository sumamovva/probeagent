"""End-to-end: a target that returns HTTP errors must score as ERROR, never Resisted.

Regression guard for the false-negative where a non-2xx response body (e.g. a 404
from a bare host missing the /v1/chat/completions path) was graded as the agent
"Resisting" — telling the user their untested target was safe. The full chain runs
with a real HTTPTarget (only the socket is mocked by respx).
"""

import json

import httpx
import pytest
import respx

from probeagent.core.engine import AttackEngine
from probeagent.core.models import AttackOutcome, OutputFormat, ProbeConfig, TargetInfo, Verdict
from probeagent.core.reporter import Reporter
from probeagent.core.scoring import calculate_resilience_score


@respx.mock
@pytest.mark.asyncio
async def test_http_404_target_scores_error_not_resisted():
    # Every request 404s — the classic "wrong endpoint path" misconfiguration.
    respx.post("https://unreachable.example/").mock(
        return_value=httpx.Response(
            404, json={"detail": "Not Found"}, headers={"content-type": "application/json"}
        )
    )

    config = ProbeConfig(
        target_url="https://unreachable.example/",
        profile="quick",
        attacks=["prompt_injection", "credential_exfil"],
        max_turns=1,
        target_type="http",
    )
    results = await AttackEngine(config).run()

    assert results
    # The bug: these came back Resisted. The fix: every one is an ERROR with no verdict.
    assert all(r.outcome == AttackOutcome.ERROR for r in results)
    assert all(r.verdict is None for r in results)
    assert all("404" in (r.error or "") for r in results)
    assert not any(r.verdict == Verdict.RESISTED for r in results)

    score = calculate_resilience_score(results)
    # A run we never reached must NOT read as safe.
    assert score.headline_verdict != Verdict.RESISTED
    assert score.headline_verdict is None
    assert score.resisted == 0
    assert score.compromised == 0
    assert score.errors == len(results)

    # Machine output carries an actionable caution (not a green bill of health).
    info = TargetInfo(url=config.target_url, reachable=True, detected_format="json_api")
    data = json.loads(Reporter().report(score, info, config, OutputFormat.JSON))
    assert data["resilience_score"]["headline_verdict"] != "Resisted"
    caution = data["resilience_score"]["caution"]
    assert caution is not None and "not exercised" in caution
