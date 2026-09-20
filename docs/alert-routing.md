# Alert routing examples

How to turn AIWall detection hits into push notifications. Two layers:

1. **Gateway alerts** — AIWall itself notifies on policy outcomes (no SIEM required).
2. **SIEM / Loki alerts** — fire when Wazuh rules or LogQL queries match exported audit JSONL.

## Rule id cheat sheet

| Wazuh | Sigma / Loki id | Audit reason | Typical severity |
|---|---|---|---|
| 107210 | `aiwall_secret_leak_blocked` | `secret-detected` | high |
| 107211 | `aiwall_policy_block` | `category-blocked` | medium |
| 107212 | `aiwall_cost_threshold` | `cost-threshold` | medium |
| 107216 | `aiwall_cost_threshold` | `cost-budget` | medium |
| 107213 | `aiwall_daily_limit` | `daily-limit` | medium |
| 107214 | `aiwall_agent_approval_denied` | `approval-denied` | high |
| 107215 | `aiwall_agent_shell_risk` | `shell risk…` | medium |
| 107217 | `aiwall_prompt_injection` | `injection-detected` | high |
| 107218 | `aiwall_jailbreak` | `jailbreak-detected` | high |
| — | `aiwall_secret_redacted` | `secret-redacted` | info |
| — | `aiwall_upstream_error` | `decision=error` | medium |

## 1. AIWall gateway (ntfy / webhook)

Configure in `aiwall.yaml` (see [AIWall configuration — alerts](https://github.com/MohsenBahremani/AIWall/blob/main/docs/configuration.md)):

```yaml
alerts:
  - channel: ntfy
    topic: aiwall-alerts
    # server: https://ntfy.home.local   # optional; default https://ntfy.sh
    "on": [secret_blocked, policy_blocked, cost_threshold, daily_limit, approval_required, provider_error]
  - channel: webhook
    url: https://ha.local/api/webhook/aiwall
    "on": [secret_blocked, policy_blocked, approval_required]
```

Subscribe on a phone: `ntfy` app → topic `aiwall-alerts`.  
Home Assistant: create an **Incoming Webhook** automation that receives the JSON POST (`trigger`, `reason`, `policy_id`, `request_id`, …).

These fire from the gateway **before** SIEM — useful on a single-host lab.

## 2. Wazuh → ntfy (by rule id)

After installing [`wazuh/rules/aiwall_rules.xml`](../wazuh/rules/aiwall_rules.xml), route high-severity AIWall rules with an integrator script or custom active-response. Minimal example using `curl` from a custom script invoked by Wazuh (replace paths and tokens):

```bash
#!/usr/bin/env bash
# /var/ossec/active-response/bin/aiwall-ntfy.sh
# Wazuh passes alert JSON on stdin for some integrations; adapt to your integrator.
set -euo pipefail
ALERT_JSON="$(cat)"
RULE_ID="$(printf '%s' "$ALERT_JSON" | python3 -c 'import json,sys; print(json.load(sys.stdin).get("rule",{}).get("id",""))')"
case "$RULE_ID" in
  107210|107214|107217|107218) PRIORITY=high; TAGS="warning,aiwall,skull" ;;
  107211|107212|107213|107215|107216) PRIORITY=default; TAGS="aiwall" ;;
  *) exit 0 ;;
esac
TITLE="AIWall Wazuh rule ${RULE_ID}"
BODY="$(printf '%s' "$ALERT_JSON" | python3 -c 'import json,sys; a=json.load(sys.stdin); print(a.get("rule",{}).get("description",""))')"
curl -fsS -d "$BODY" \
  -H "Title: $TITLE" \
  -H "Priority: $PRIORITY" \
  -H "Tags: $TAGS" \
  "https://ntfy.sh/aiwall-alerts"
```

Wire the script in Wazuh via an **integrator** or **active-response** that filters on `rule.id` in `107210-107215`. Exact XML depends on your Wazuh version — see [Wazuh integrator docs](https://documentation.wazuh.com/current/user-manual/manager/manual-integration.html).

## 3. Wazuh → generic webhook

Same idea: POST the alert JSON to Discord/Slack/Home Assistant:

```bash
curl -fsS -X POST "https://ha.local/api/webhook/aiwall-siem" \
  -H "Content-Type: application/json" \
  -d "$ALERT_JSON"
```

Map rule ids in HA: if `rule.id == 107210` → notify parents; if `107214` → notify admin on agent deny.

## 4. Grafana / Loki alerts

Paste LogQL from [`loki/queries.json`](../loki/queries.json) into Grafana Alerting. Example for secret leaks:

```logql
{job="aiwall"} | json | schema="aiwall.audit.v1" | decision="block" | reason="secret-detected"
```

Create one alert rule per detection id (`aiwall_secret_leak_blocked`, `aiwall_agent_approval_denied`, …). Contact point: ntfy, webhook, or email.

Sample stack: `cd grafana && docker compose up -d` — then Explore → Alert.

## Verify without production SIEM

```bash
# Offline: packs still match the sample corpus
python3 validation/validate_rules.py

# Lab: export live events, then feed Wazuh logtest or Loki
curl -OJ "http://127.0.0.1:8080/events/export.jsonl?window_hours=24"
```

Triage steps after an alert fires: [playbooks/](../playbooks/).
