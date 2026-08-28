# Red team → detections bridge

Connects [AIWall-redteam](https://github.com/MohsenBah/AIWall-redteam) technique IDs to the sample audit corpus and SIEM packs in this repo.

Machine-readable map: [`validation/redteam_bridge.json`](../validation/redteam_bridge.json) (checked by `validation/validate_rules.py`).

## How to read the map

| Field | Meaning |
|---|---|
| `technique_id` | Payload id in `AIWall-redteam/payloads/` (e.g. `SE-01`) |
| `sample_request_id` | Line in `validation/samples/aiwall.audit.v1.sample.jsonl` |
| `wazuh_rule_id` / `sigma_rule` | Alert that should fire on that sample |
| `detection_gap: true` | Campaign may run, but Community detections do not yet have a dedicated rule |

## Covered holds (today)

| Technique | Sample | Wazuh | Sigma |
|---|---|---|---|
| SE-01 … SE-03 | `req-secret-001` (+ redact alt) | 100210 | `aiwall_secret_leak_blocked` |
| UC-01, UC-02 | `req-policy-001` | 100211 | `aiwall_policy_block` |
| CA-01 | `req-cost-001` | 100212 | `aiwall_cost_threshold` |
| CA-03 | `req-cost-002` | 100212 | `aiwall_cost_threshold` |
| CA-02 | `req-limit-001` | 100213 | `aiwall_daily_limit` |
| AT-01 | `req-agent-001` | 100214 | `aiwall_agent_approval_denied` |
| AT-03 | `req-warn-001` | 100215 | `aiwall_agent_shell_risk` |

## Gaps (need core or new samples)

- **PI-01 / PI-03** — prompt injection / meta-prompt; no stable audit reason to detect.
- **AT-02** — sensitive file access; awaiting a dedicated sample reason.
- **PI-02** — only adjacent via `category-blocked`, not a jailbreak-specific rule.

## Regression preference

Preferred loop:

1. Run a red-team campaign or `scripts/run_regression.py` against a lab AIWall.
2. Export `GET /events/export.jsonl`.
3. Diff new hold reasons against this bridge; add sample lines + expected hits when a new stable reason appears.
4. `python3 validation/validate_rules.py`.
