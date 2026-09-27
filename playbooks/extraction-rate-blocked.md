# Playbook: Extraction rate / high-volume query blocked

**Trigger:** AIWall blocked a request because billable volume in the rolling
`rate_limits` window exceeded `max_requests` or `max_tokens`.

| Signal | Value |
|---|---|
| Audit `decision` | `block` |
| Audit `reason` | `extraction-rate` |
| Wazuh | Rule **107219** |
| Sigma / Loki | `aiwall_extraction_rate` |
| ATLAS | [AML.T0024](https://atlas.mitre.org/) Exfiltration via ML Inference API |
| Sample | `req-extract-001` |
| Red-team | SE-03 (high-volume inference-path floods) |

Upstream behavior: AIWall `docs/configuration.md` (`rate_limits`) and
`docs/audit-export.md` (`extraction-rate`).

## Triage (5–15 min)

1. **Confirm the event** in AIWall Events / Blocked or:
   ```bash
   curl -sS "http://127.0.0.1:8080/events/export.jsonl?decision=block&window_hours=24" \
     | jq 'select(.reason=="extraction-rate")'
   ```
2. Note `request_id`, `timestamp`, `user_id` / profile, `provider`, `model`,
   `total_tokens` if present.
3. Classify intent:
   - Accidental loop (script / agent retrying)
   - Shared lab hitting a low cap
   - Deliberate high-volume extraction (many similar prompts, large completions)
4. Compare nearby allows from the same `user_id` in the configured
   `window_seconds` (default 300).

## Response

| Priority | Action |
|---|---|
| P1 | If the client is a production profile key, rotate it and inspect recent allows for data-harvest patterns. |
| P2 | Keep `rate_limits.enabled` on shared gateways; raise `max_requests` / `max_tokens` only with a documented reason. |
| P2 | Pair with secret-leak alerts — extraction floods plus `secret-detected` is a higher-priority incident. |
| P3 | Daily profile caps (`daily-limit`) still apply; do not disable them in favor of the rolling window. |

## Close-out

- Link the blocking `request_id`s and the `rate_limits` values in effect.
- Re-run a short burst test after any cap change.
