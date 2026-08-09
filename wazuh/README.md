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

### Install

```bash
sudo cp wazuh/decoders/aiwall_decoders.xml /var/ossec/etc/decoders/
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

### Verify with wazuh-logtest

```bash
sudo /var/ossec/bin/wazuh-logtest < validation/samples/aiwall.audit.v1.sample.jsonl
```

Expect decoder name `aiwall-audit` and named fields such as `decision`, `reason`, `policy_id`.

Without a Wazuh manager, run the offline check:

```bash
python3 wazuh/tests/test_decoder_fields.py
```

### Rules

Rules that fire on secret-leak / policy / cost / daily-limit land in Phase 6.3 under `wazuh/rules/`.
