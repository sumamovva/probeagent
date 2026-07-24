# JSON report schema

`probeagent attack ... --output json` writes a machine-readable report for CI gates,
dashboards, and remediation tooling. The report is indented JSON and contains four
top-level sections.

## Top-level object

| Key | Type | Meaning |
| --- | --- | --- |
| `probeagent_version` | string | ProbeAgent version that produced the report. |
| `timestamp` | string | Report creation time in ISO 8601 format. |
| `target` | object | Reachability and format information for the tested endpoint. |
| `config` | object | Profile and execution settings used for the scan. |
| `resilience_score` | object | Aggregate verdict and count summary. |
| `attack_summaries` | array | One aggregate row per attack strategy. |
| `attack_results` | array | One detailed result per executed strategy. |

## `target`

| Key | Type | Meaning |
| --- | --- | --- |
| `url` | string | Endpoint that was tested. |
| `reachable` | boolean | Whether the target produced a reachable response. |
| `response_time_ms` | number or null | Detected response time in milliseconds. |
| `detected_format` | string or null | Response format detected by the target adapter. |

## `config`

| Key | Type | Meaning |
| --- | --- | --- |
| `profile` | string | Attack profile, such as `quick`, `standard`, or `thorough`. |
| `attacks` | array of strings | Explicit attack names, when supplied. |
| `max_turns` | integer | Maximum turns allowed for a strategy. |
| `attacker_model` | string or null | Model used to generate attack turns. |

## `resilience_score`

| Key | Type | Meaning |
| --- | --- | --- |
| `headline_verdict` | string or null | Overall worst-case verdict: `Compromised`, `Blocked`, or `Resisted`. |
| `verdict_breakdown` | object | Counts for `compromised`, `resisted`, and `blocked`. |
| `caution` | string or null | Warning when errors or upstream blocks could make the result misleading. |
| `total` | integer | Total strategy results. |
| `succeeded` | integer | Strategies whose attack goal succeeded. |
| `failed` | integer | Strategies whose attack goal failed. |
| `errors` | integer | Strategies that could not produce a gradeable result. |
| `skipped` | integer | Strategies not run. |
| `highest_severity_succeeded` | string or null | Highest severity among successful attacks. |

## `attack_summaries`

Each item contains `attack_name`, `display_name`, `severity`, `verdict`, `total`,
`succeeded`, `failed`, and `success_rate`. It also contains:

- `framework_tags`: objects with `code`, `title`, and `scheme` (`LLM` or `ASI`)
- `mitre_atlas`: objects with `id` and resolved technique `name`

## `attack_results`

Each detailed result contains `id`, `attack_name`, `outcome`, `verdict`, `severity`,
`success`, `framework_tags`, `mitre_atlas`, `blocked_by`, `execution_time`,
`score_rationale`, `error`, `turns`, and `metadata`.

`outcome` is one of `succeeded`, `failed`, `error`, `skipped`, or `undetermined`.
`blocked_by` is the matched guardrail signature, or `null` when no detectable
guardrail blocked the request. `turns` is an array of `{ "role", "content" }`
objects. `metadata` is an object reserved for strategy-specific data.

## Minimal example

```json
{
  "probeagent_version": "0.3.5",
  "timestamp": "2025-01-15T12:00:00+00:00",
  "target": {
    "url": "https://agent.example.com/v1/chat/completions",
    "reachable": true,
    "response_time_ms": 412.7,
    "detected_format": "openai-chat"
  },
  "config": {
    "profile": "quick",
    "attacks": [],
    "max_turns": 1,
    "attacker_model": null
  },
  "resilience_score": {
    "headline_verdict": "Resisted",
    "verdict_breakdown": {
      "compromised": 0,
      "resisted": 5,
      "blocked": 0
    },
    "caution": null,
    "total": 5,
    "succeeded": 0,
    "failed": 5,
    "errors": 0,
    "skipped": 0,
    "highest_severity_succeeded": null
  },
  "attack_summaries": [],
  "attack_results": []
}
```

The exact set of attack summaries and detailed results depends on the selected
profile and the target response.
