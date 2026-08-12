# Playbook: Secret leak detected

**Trigger:** AIWall blocked (or redacted) an outbound prompt because a secret matched the scanner.

| Signal | Value |
|---|---|
| Audit `decision` | `block` (hard stop) or `redact` (masked then forwarded) |
| Audit `reason` | `secret-detected` or `secret-redacted` |
| Wazuh | Rule **100210** (`secret-detected` only) |
| Sigma / Loki | `aiwall_secret_leak_blocked` / `aiwall_secret_redacted` |
| ATLAS | [AML.T0057](https://atlas.mitre.org/) LLM Data Leakage |
| Sample | `req-secret-001`, `req-redact-001` |

Upstream behavior: [AIWall secret-scanning.md](https://github.com/MohsenBah/AIWall/blob/main/docs/secret-scanning.md).

## Triage (5–15 min)

1. **Confirm the event** in AIWall Events / Blocked, Grafana **AIWall Overview**, or:
   ```bash
   curl -sS "http://127.0.0.1:8080/events/export.jsonl?decision=block&window_hours=24" \
     | jq 'select(.reason=="secret-detected")'
   ```
2. Note **privacy-safe** fields only: `request_id`, `timestamp`, `user_id` / profile, `provider`, `model`, `matched_rule_ids`, `policy_id`.  
   AIWall does **not** store the raw secret in audit export.
3. Classify intent:
   - Accidental paste (most common in developer workflows)
   - Repeated / automated client sending env dumps
   - Child or shared profile (check role / key)
4. Check **volume**: one-off vs burst of the same `matched_rule_ids` from one profile or client IP (gateway logs).
5. If `decision=redact`, treat as a near-miss: the provider may still have seen a masked prompt — still rotate if the original value was live.

## Response

| Priority | Action |
|---|---|
| P1 | **Assume the credential is compromised** if it was a live production secret and the request was `allow`/`redact`/`warn` to a third-party provider, or if you cannot prove the block happened before egress. |
| P1 | **Rotate / revoke** the matching secret type (`aws-access-key`, `github-token`, `slack-token`, …). Follow your cloud/SCM vendor’s revoke flow. |
| P2 | Identify the **source client** (Open WebUI profile key, IDE extension, script) via `user_id` and how that key is issued. |
| P2 | Remove the secret from local notes, chat history, and agent context if the client retains transcripts. |
| P3 | Tune policy if needed: keep `block` for production secrets; use `redact`/`warn` only where you accept residual risk. |

## Containment checklist

- [ ] Secret revoked / rotated; old value invalidated
- [ ] Profile API key rotated if it was shared or leaked alongside the secret
- [ ] No further `secret-detected` / `secret-redacted` events from the same profile in the next hour
- [ ] Parent/admin notified if a **child** profile was involved

## False positives

- Intentional scanner self-tests with **fake** tokens (e.g. documentation placeholders AIWall already allowlists — real-looking fakes still fire)
- Pasting public example keys from vendor docs that look like live credentials
- High-entropy blobs that are not secrets (`high-entropy` heuristic)

Document the `request_id` and mark the alert as FP in your SIEM; do not weaken detectors without a replacement control.

## Related

- Coverage: [docs/coverage-matrix.md](../docs/coverage-matrix.md)
- Loki: `{job="aiwall"} | json | decision="block" | reason="secret-detected"`
- Sibling playbooks: [child-safety-block.md](child-safety-block.md), [suspicious-agent-action.md](suspicious-agent-action.md)
