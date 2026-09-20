# Red team → detections bridge

Connects [AIWall-redteam](https://github.com/MohsenBahremani/AIWall-redteam) technique IDs to the sample audit corpus and SIEM packs in this repo.

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
| SE-01 … SE-03 | `req-secret-001` (+ redact alt) | 107210 | `aiwall_secret_leak_blocked` |
| UC-01, UC-02 | `req-policy-001` | 107211 | `aiwall_policy_block` |
| CA-01 | `req-cost-001` | 107212 | `aiwall_cost_threshold` |
| CA-03 | `req-cost-002` | 107216 | `aiwall_cost_threshold` |
| CA-02 | `req-limit-001` | 107213 | `aiwall_daily_limit` |
| AT-01 | `req-agent-001` | 107214 | `aiwall_agent_approval_denied` |
| AT-03 | `req-warn-001` | 107215 | `aiwall_agent_shell_risk` |
| PI-01 | `req-inject-001` | 107217 | `aiwall_prompt_injection` |
| PI-03 | `req-jailbreak-001` | 107218 | `aiwall_jailbreak` |

## Gaps (need core or new samples)

- **AT-02** — sensitive file access; needs a dedicated sample beyond shell/approval.
- **AML.T0024** — model-extraction / high-volume query; needs aggregate metrics from core.
- **PI-02** — adjacent via `category-blocked` only when family classifiers fire.

## Regression preference

Preferred loop:

1. Run a red-team campaign or `scripts/run_regression.py` against a lab AIWall.
2. Export `GET /events/export.jsonl`.
3. Diff new hold reasons against this bridge; add sample lines + expected hits when a new stable reason appears.
4. `python3 validation/validate_rules.py`.

## Live export check

From this repo (AIWall running on `:8080`):

```bash
./scripts/validate_export.sh
# after a red-team regression run against the same lab:
./scripts/validate_export.sh --with-regression --require-reasons secret-detected
# or score a saved file:
./scripts/validate_export.sh --file /tmp/aiwall.audit.jsonl --require-reasons secret-detected approval-denied
```
