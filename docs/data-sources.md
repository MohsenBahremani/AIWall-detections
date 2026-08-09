# Data sources

AIWall-detections consumes the frozen audit export from [AIWall](https://github.com/MohsenBah/AIWall):

**Schema:** `aiwall.audit.v1`  
**Format:** JSON Lines (NDJSON) — one event object per line  
**Upstream docs:** [AIWall `docs/audit-export.md`](https://github.com/MohsenBah/AIWall/blob/main/docs/audit-export.md)

## How to obtain events

From a running AIWall instance:

```bash
curl -OJ "http://127.0.0.1:8080/events/export.jsonl?window_hours=24"
```

Optional filters (same as the control-panel event explorer):

| Query param | Example | Meaning |
|---|---|---|
| `decision` | `block` | Only that decision |
| `provider` | `openai` | Provider name |
| `model` | `gpt-4o-mini` | Model id |
| `profile` | `3` | Profile / `user_id` |
| `window_hours` | `0` | All time (`0`); default `24` |

Ship the file (or stream equivalent lines) into Wazuh, Loki, or any NDJSON-capable pipeline.

For a local Grafana view of the sample corpus, see [`grafana/README.md`](../grafana/README.md) (`docker compose up`).

## Event shape (summary)

Every line includes `"schema":"aiwall.audit.v1"` plus privacy-safe fields: decision, reason, policy, rule ids (array), categories (array), model/provider, tokens, cost, latency. **No raw prompts.**

Full field table: see upstream `docs/audit-export.md`.

## Sample corpus

Canonical samples for decoder/rule development live under `validation/samples/`:

| File | Contents |
|---|---|
| `aiwall.audit.v1.sample.jsonl` | Mixed allow / warn / block / redact / error lines covering common reasons |

These samples use **fake** rule ids and reasons only — no real secrets.

Expected detection hits for that corpus: [`validation/expected_hits.json`](../validation/expected_hits.json).  
Run everything offline: `python3 validation/validate_rules.py` ([validation/README.md](../validation/README.md)).

## Wazuh

Decoders that turn each JSONL line into named fields:

- [`wazuh/decoders/aiwall_decoders.xml`](../wazuh/decoders/aiwall_decoders.xml)
- Alert rules (secret / policy / cost / daily-limit): [`wazuh/rules/aiwall_rules.xml`](../wazuh/rules/aiwall_rules.xml)
- Sigma mirrors: [`sigma/rules/`](../sigma/rules/) ([sigma/README.md](../sigma/README.md))
- Loki / LogQL pack: [`loki/queries.json`](../loki/queries.json) ([loki/README.md](../loki/README.md))
- Install / logtest notes: [`wazuh/README.md`](../wazuh/README.md)

## Compatibility promise

Detection content in this repo targets `aiwall.audit.v1`. A future `v2` will be documented before rules migrate. Ignore unknown fields when parsing.
