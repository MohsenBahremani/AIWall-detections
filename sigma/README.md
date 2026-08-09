# Sigma rules for AIWall

Rules target `aiwall.audit.v1` JSON Lines fields (`schema`, `decision`, `reason`, …).
They mirror the Wazuh alerts in [`../wazuh/rules/aiwall_rules.xml`](../wazuh/rules/aiwall_rules.xml).

| File | Wazuh id | Detects |
|---|---|---|
| [`rules/aiwall_secret_leak_blocked.yml`](rules/aiwall_secret_leak_blocked.yml) | 100210 | `block` + `secret-detected` |
| [`rules/aiwall_policy_block.yml`](rules/aiwall_policy_block.yml) | 100211 | `block` + `category-blocked` |
| [`rules/aiwall_cost_threshold.yml`](rules/aiwall_cost_threshold.yml) | 100212 | `block` + `cost-threshold` |
| [`rules/aiwall_daily_limit.yml`](rules/aiwall_daily_limit.yml) | 100213 | `block` + `daily-limit` |

## Validate / convert

```bash
# from AIWall-detections/
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
python3 sigma/tests/test_sigma_convert.py
```

The test loads every rule with pySigma and converts it to **Elasticsearch Lucene** queries (one backend). It also checks that each rule matches the expected sample line from `validation/samples/aiwall.audit.v1.sample.jsonl`.
