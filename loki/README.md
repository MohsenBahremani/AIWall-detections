# Loki / LogQL query pack for AIWall

Queries target `aiwall.audit.v1` JSON Lines shipped to Loki (label `job=aiwall`).
They mirror the Wazuh / Sigma alerts and cover a few extra triage cases from the sample corpus.

Pack file: [`queries.json`](queries.json)

| Id | Detects | Sample hit(s) |
|---|---|---|
| `aiwall_secret_leak_blocked` | `block` + `secret-detected` (Wazuh 100210) | `req-secret-001` |
| `aiwall_policy_block` | `block` + `category-blocked` (100211) | `req-policy-001` |
| `aiwall_cost_threshold` | `block` + `cost-threshold` (100212) | `req-cost-001` |
| `aiwall_daily_limit` | `block` + `daily-limit` (100213) | `req-limit-001` |
| `aiwall_all_blocks` | all `decision=block` | five block samples |
| `aiwall_agent_approval_denied` | `block` + `approval-denied` | `req-agent-001` |
| `aiwall_secret_redacted` | `redact` + `secret-redacted` | `req-redact-001` |
| `aiwall_upstream_error` | `decision=error` | `req-error-001` |

## Try against the sample stack

```bash
cd grafana && docker compose up -d
# Grafana Explore → datasource AIWall Loki → paste a `logql` string from queries.json
# Time range: Last 1 hour (Promtail uses ingest time for the sample file)
```

## Offline check

```bash
python3 loki/tests/test_logql_match.py
```

Asserts each query’s filters match exactly the listed `request_id`s in
`validation/samples/aiwall.audit.v1.sample.jsonl`, and that the published LogQL
string includes those same `| field="value"` clauses.
