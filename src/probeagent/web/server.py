# Copyright 2025 Suma Movva
# SPDX-License-Identifier: Apache-2.0

"""FastAPI server for the War Room tactical display UI."""

from __future__ import annotations

import asyncio
import json
import tempfile
import uuid
from html import escape
from pathlib import Path

from fastapi import FastAPI, Request, WebSocket, WebSocketDisconnect
from fastapi.responses import HTMLResponse
from pydantic import BaseModel

from probeagent.attacks import ATTACK_REGISTRY
from probeagent.core.engine import AttackEngine, _ATTACK_CLASSES
from probeagent.core.models import AttackOutcome, ProbeConfig
from probeagent.core.scoring import calculate_resilience_score
from probeagent.utils.config import load_profile

app = FastAPI(title="ProbeAgent Arcade")

_GAME_HTML = Path(__file__).parent / "game.html"

# Active scan sessions: session_id -> asyncio.Queue of JSON events
_sessions: dict[str, asyncio.Queue] = {}

# Temp file for CLI → server IPC (most reliable pre-fill mechanism)
PREFILL_PATH = Path(tempfile.gettempdir()) / "probeagent_game_prefill.json"


def _read_prefill() -> dict[str, str]:
    """Read pre-fill config from temp file written by CLI."""
    if PREFILL_PATH.exists():
        try:
            return json.loads(PREFILL_PATH.read_text())
        except (json.JSONDecodeError, OSError):
            pass
    return {}


class StartRequest(BaseModel):
    url: str
    profile: str = "quick"
    target_type: str = "http"


@app.get("/", response_class=HTMLResponse)
async def index(request: Request):
    html = _GAME_HTML.read_text()

    # Read pre-fill from temp file (written by CLI before server starts)
    prefill = _read_prefill()

    # Query params override temp file values
    target = request.query_params.get("target", "") or prefill.get("target", "")
    profile = request.query_params.get("profile", "") or prefill.get("profile", "")
    target_type = request.query_params.get("type", "") or prefill.get("type", "")
    autostart = request.query_params.get("autostart", "") or prefill.get("autostart", "")

    # Inject target URL directly into the HTML input value attribute (no JS needed)
    if target:
        safe_target = escape(target, quote=True)
        html = html.replace(
            'id="target-url" placeholder=',
            f'id="target-url" value="{safe_target}" placeholder=',
        )

    # Inject profile/type/autostart via JS (buttons need script to toggle classes)
    if profile or target_type or autostart:
        inject = (
            "<script>"
            "window.__PREFILL__="
            + json.dumps(
                {
                    "target": target,
                    "profile": profile,
                    "type": target_type,
                    "autostart": autostart,
                }
            )
            + ";</script>"
        )
        html = html.replace("<script>", inject + "<script>", 1)

    return HTMLResponse(
        content=html,
        headers={"Cache-Control": "no-store, no-cache, must-revalidate, max-age=0"},
    )


@app.get("/api/prefill")
async def get_prefill():
    """Return current pre-fill values (used by JS on tab focus)."""
    return _read_prefill()


@app.post("/api/start")
async def start_scan(req: StartRequest):
    session_id = str(uuid.uuid4())[:8]
    queue: asyncio.Queue = asyncio.Queue()
    _sessions[session_id] = queue

    asyncio.create_task(_run_scan(session_id, req, queue))
    return {"session_id": session_id}


@app.websocket("/ws/{session_id}")
async def ws_endpoint(websocket: WebSocket, session_id: str):
    await websocket.accept()
    queue = _sessions.get(session_id)
    if not queue:
        await websocket.send_json({"type": "error", "message": "Unknown session"})
        await websocket.close()
        return

    try:
        while True:
            event = await queue.get()
            await websocket.send_json(event)
            if event.get("type") == "scan_complete":
                break
    except WebSocketDisconnect:
        pass
    finally:
        _sessions.pop(session_id, None)


async def _run_scan(session_id: str, req: StartRequest, queue: asyncio.Queue):
    """Run the attack scan and push events to the queue."""
    try:
        profile_data = load_profile(req.profile)
    except FileNotFoundError:
        await queue.put({"type": "error", "message": f"Unknown profile: {req.profile}"})
        await queue.put({"type": "scan_complete", "grade": "Error", "summary": {}})
        return

    config = ProbeConfig(
        target_url=req.url,
        profile=req.profile,
        attacks=profile_data.get("attacks", []),
        max_turns=profile_data.get("max_turns", 1),
        attacker_model=profile_data.get("attacker_model", "gpt-4"),
        target_type=req.target_type,
        timeout=30.0,
    )

    engine = AttackEngine(config)
    target = engine._create_target()

    try:
        info = await target.validate()
        if not info.reachable:
            await queue.put({"type": "error", "message": f"Target unreachable: {info.error}"})
            await queue.put({"type": "scan_complete", "grade": "Error", "summary": {}})
            return

        await queue.put(
            {
                "type": "connected",
                "target": req.url,
                "format": info.detected_format,
                "latency_ms": info.response_time_ms,
            }
        )

        # Count total strategies across all attacks
        total_strategies = 0
        attack_plan = []
        for attack_name in config.attacks:
            cls = _ATTACK_CLASSES.get(attack_name)
            if cls is None:
                continue
            attack = cls()
            # Get strategy count from the module
            mod = __import__(f"probeagent.attacks.{attack_name}", fromlist=["STRATEGIES"])
            strategies = getattr(mod, "STRATEGIES", [])
            count = len(strategies)
            total_strategies += count
            attack_plan.append((attack_name, attack, strategies, count))

        await queue.put(
            {
                "type": "mission_brief",
                "attacks": [
                    {
                        "name": name,
                        "display_name": ATTACK_REGISTRY.get(name, {}).get("display_name", name),
                        "severity": ATTACK_REGISTRY.get(name, {}).get("severity", "medium").value
                        if hasattr(ATTACK_REGISTRY.get(name, {}).get("severity", "medium"), "value")
                        else "medium",
                        "strategy_count": count,
                    }
                    for name, _, _, count in attack_plan
                ],
                "total_strategies": total_strategies,
            }
        )

        all_results = []
        global_index = 0

        for attack_name, attack_instance, strategies, strategy_count in attack_plan:
            category_results = []

            for strategy in strategies:
                global_index += 1
                strategy_name = strategy.get("name", "unknown")

                await queue.put(
                    {
                        "type": "attack_start",
                        "category": attack_name,
                        "strategy": strategy_name,
                        "index": global_index,
                        "total": total_strategies,
                        "severity": ATTACK_REGISTRY.get(attack_name, {})
                        .get("severity", "medium")
                        .value
                        if hasattr(
                            ATTACK_REGISTRY.get(attack_name, {}).get("severity", "medium"), "value"
                        )
                        else "medium",
                    }
                )

                # Run single strategy
                turns_to_run = strategy["turns"][: config.max_turns]
                try:
                    result = await attack_instance._run_strategy(target, strategy, turns_to_run)
                except Exception:
                    # Fallback: run entire attack and match
                    result_list = await attack_instance.execute(
                        target, max_turns=config.max_turns, attacker_model=config.attacker_model
                    )
                    result = result_list[0] if result_list else None
                    if result is None:
                        continue

                category_results.append(result)
                all_results.append(result)

                # Build transcript preview
                transcript_preview = ""
                if result.turns:
                    for turn in result.turns[-2:]:
                        prefix = ">" if turn.role == "attacker" else "<"
                        content = turn.content[:200]
                        transcript_preview += f"{prefix} {content}\n"

                await queue.put(
                    {
                        "type": "attack_result",
                        "category": attack_name,
                        "strategy": strategy_name,
                        "outcome": result.outcome.value,
                        "severity": result.severity.value,
                        "rationale": result.score_rationale[:300],
                        "transcript_preview": transcript_preview,
                        "index": global_index,
                        "total": total_strategies,
                    }
                )

                # Brief pause for animation
                await asyncio.sleep(0.1)

            succeeded = sum(1 for r in category_results if r.outcome == AttackOutcome.SUCCEEDED)
            await queue.put(
                {
                    "type": "category_done",
                    "category": attack_name,
                    "display_name": ATTACK_REGISTRY.get(attack_name, {}).get(
                        "display_name", attack_name
                    ),
                    "succeeded": succeeded,
                    "total": len(category_results),
                }
            )

        # Final score
        score = calculate_resilience_score(all_results)
        await queue.put(
            {
                "type": "scan_complete",
                "grade": score.grade.value,
                "summary": {
                    "total": score.total,
                    "succeeded": score.succeeded,
                    "failed": score.failed,
                    "errors": score.errors,
                    "highest_severity": score.highest_severity_succeeded.value
                    if score.highest_severity_succeeded
                    else None,
                },
                "results": [
                    {
                        "attack_name": r.attack_name,
                        "strategy": r.metadata.get("strategy", ""),
                        "outcome": r.outcome.value,
                        "severity": r.severity.value,
                        "rationale": r.score_rationale,
                        "turns": [{"role": t.role, "content": t.content} for t in r.turns],
                    }
                    for r in all_results
                ],
            }
        )

    except Exception as exc:
        await queue.put({"type": "error", "message": str(exc)})
        await queue.put({"type": "scan_complete", "grade": "Error", "summary": {}})
    finally:
        await target.close()
