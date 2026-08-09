# Wazuh content for AIWall

## Decoders (Phase 6.2)

File: [`decoders/aiwall_decoders.xml`](decoders/aiwall_decoders.xml)

Matches `aiwall.audit.v1` JSON Lines and extracts fields via Wazuh `JSON_Decoder`:

| Dynamic field | Source |
|---|---|
| `schema` | always `aiwall.audit.v1` |
| `id`, `timestamp`, `request_id` | event identity |
| `user_id`, `provider`, `model` | context |
| `decision`, `reason`, `policy_id` | outcome |
| `matched_rule_ids`, `categories` | arrays |
| `input_length`, `output_length`, `*_tokens`, `estimated_cost`, `redaction_count`, `latency_ms` | metrics |

## Rules (Phase 6.3)

File: [`rules/aiwall_rules.xml`](rules/aiwall_rules.xml)

| Rule id | Level | When |
|---|---|---|
| `100200` / `100201` | 0 | Parent: any AIWall audit event (jsonl / syslog) |
| `100210` | 12 | `decision=block` + `reason=secret-detected` |
| `100211` | 10 | `decision=block` + `reason=category-blocked` |
| `100212` | 10 | `decision=block` + `reason=cost-threshold` |
| `100213` | 10 | `decision=block` + `reason=daily-limit` |

## Install

```bash
sudo cp wazuh/decoders/aiwall_decoders.xml /var/ossec/etc/decoders/
sudo cp wazuh/rules/aiwall_rules.xml /var/ossec/etc/rules/
sudo systemctl restart wazuh-manager
```

Point a `<localfile>` (or agent) at AIWall JSONL, for example:

```xml
<localfile>
  <log_format>json</log_format>
  <location>/var/log/aiwall/audit.jsonl</location>
</localfile>
```

Or ship lines under syslog program name `aiwall` (uses the `aiwall-audit-syslog*` decoders).

## Verify

With a Wazuh manager:

```bash
sudo /var/ossec/bin/wazuh-logtest < validation/samples/aiwall.audit.v1.sample.jsonl
```

Expect decoder `aiwall-audit` and rule ids `100210`–`100213` on the matching sample lines.

Without Wazuh, offline checks:

```bash
python3 wazuh/tests/test_decoder_fields.py
python3 wazuh/tests/test_rules_match.py
```
