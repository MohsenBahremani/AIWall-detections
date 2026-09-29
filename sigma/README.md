# Sigma rules for AIWall

Rules target `aiwall.audit.v1` JSON Lines fields (`schema`, `decision`, `reason`, …).
They mirror the Wazuh alerts in [`../wazuh/rules/aiwall_rules.xml`](../wazuh/rules/aiwall_rules.xml).

| File | Wazuh id | Detects |
|---|---|---|
| [`rules/aiwall_secret_leak_blocked.yml`](rules/aiwall_secret_leak_blocked.yml) | 107210 | `block` + `secret-detected` |
| [`rules/aiwall_policy_block.yml`](rules/aiwall_policy_block.yml) | 107211 | `block` + `category-blocked` |
| [`rules/aiwall_cost_threshold.yml`](rules/aiwall_cost_threshold.yml) | 107212 | `block` + `cost-threshold` or `cost-budget` |
| [`rules/aiwall_daily_limit.yml`](rules/aiwall_daily_limit.yml) | 107213 | `block` + `daily-limit` |
| [`rules/aiwall_agent_approval_denied.yml`](rules/aiwall_agent_approval_denied.yml) | 107214 | `block` + `approval-denied` |
| [`rules/aiwall_agent_shell_risk.yml`](rules/aiwall_agent_shell_risk.yml) | 107215 | `warn` + `reason` starts with `shell risk` |
| [`rules/aiwall_prompt_injection.yml`](rules/aiwall_prompt_injection.yml) | 107217 | `block` + `injection-detected` |
| [`rules/aiwall_jailbreak.yml`](rules/aiwall_jailbreak.yml) | 107218 | `block` + `jailbreak-detected` |
| [`rules/aiwall_extraction_rate.yml`](rules/aiwall_extraction_rate.yml) | 107219 | `block` + `extraction-rate` |
| [`rules/aiwall_sensitive_file_access.yml`](rules/aiwall_sensitive_file_access.yml) | 107220 | `block` + `reason` starts with `sensitive-file-access` |
| [`rules/aiwall_output_secret_blocked.yml`](rules/aiwall_output_secret_blocked.yml) | 107221 | `block` + `output-secret-detected` |

## Validate / convert

```bash
# from AIWall-detections/
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
python3 sigma/tests/test_sigma_convert.py
```

The test loads every rule with pySigma and converts it to **Elasticsearch Lucene** queries (one backend). It also checks that each rule matches the expected sample line from `validation/samples/aiwall.audit.v1.sample.jsonl`.
