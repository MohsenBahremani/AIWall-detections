# Wazuh content for AIWall

## Decoders

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

## Rules

File: [`rules/aiwall_rules.xml`](rules/aiwall_rules.xml)

| Rule id | Level | When |
|---|---|---|
| `107200` / `107201` | 0 | Parent: AIWall audit (`decoded_as=json` + `schema=aiwall.audit.v1` for JSONL; syslog decoder for agent/syslog) |
| `107210` | 12 | `decision=block` + `reason=secret-detected` |
| `107211` | 10 | `decision=block` + `reason=category-blocked` |
| `107212` | 10 | `decision=block` + `reason=cost-threshold` |
| `107216` | 10 | `decision=block` + `reason=cost-budget` |
| `107213` | 10 | `decision=block` + `reason=daily-limit` |
| `107214` | 12 | `decision=block` + `reason=approval-denied` |
| `107215` | 7 | `decision=warn` + `reason` starts with `shell risk` |

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

With `<log_format>json</log_format>`, Wazuh uses its built-in **`json`** decoder (not the custom `aiwall-audit` decoder name). Parent rule **107200** matches `decoded_as=json` plus `schema=aiwall.audit.v1`.

Or ship lines under syslog program name `aiwall` (uses the `aiwall-audit-syslog*` decoders).

## Verify

With a Wazuh manager:

```bash
sudo /var/ossec/bin/wazuh-logtest < validation/samples/aiwall.audit.v1.sample.jsonl
```

Expect `decoded_as=json` and rule ids `107210`–`107215` (plus `107216` for `cost-budget`) on the matching sample lines when using `<log_format>json</log_format>`.

Without Wazuh, offline checks:

```bash
python3 wazuh/tests/test_decoder_fields.py
python3 wazuh/tests/test_rules_match.py
```
