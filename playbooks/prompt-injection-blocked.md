# Playbook: Prompt injection / jailbreak blocked

**Trigger:** AIWall blocked an outbound prompt that matched instruction-override,
jailbreak-persona, or meta-prompt extraction patterns.

| Signal | Value |
|---|---|
| Audit `decision` | `block` |
| Audit `reason` | `injection-detected` or `jailbreak-detected` |
| Wazuh | Rule **107217** (`injection-detected`) or **107218** (`jailbreak-detected`) |
| Sigma / Loki | `aiwall_prompt_injection` / `aiwall_jailbreak` |
| ATLAS | [AML.T0051](https://atlas.mitre.org/) Prompt Injection; [AML.T0054](https://atlas.mitre.org/) Jailbreak; [AML.T0056](https://atlas.mitre.org/) Meta Prompt Extraction |
| Sample | `req-inject-001`, `req-jailbreak-001` |
| Red-team | PI-01, PI-03 |

Upstream behavior: AIWall `docs/audit-export.md` and `docs/configuration.md`
(`input.contains_injection` / `input.contains_jailbreak`).

## Triage (5–15 min)

1. **Confirm the event** in AIWall Events / Blocked, Grafana **AIWall Overview**, or:
   ```bash
   curl -sS "http://127.0.0.1:8080/events/export.jsonl?decision=block&window_hours=24" \
     | jq 'select(.reason=="injection-detected" or .reason=="jailbreak-detected")'
   ```
2. Note privacy-safe fields: `request_id`, `timestamp`, `user_id` / profile, `provider`,
   `model`, `policy_id`, `reason`.
3. Classify intent:
   - Accidental paste of a public jailbreak recipe during testing
   - Deliberate red-team / QA campaign (expected)
   - Repeated probes from one profile or client (possible abuse)
4. Check volume: one-off vs burst of the same `reason` from one `user_id`.
5. If the client is a coding agent, review whether tool policies also fired nearby.

## Response

| Priority | Action |
|---|---|
| P1 | If the probe came from a production/shared profile key, rotate that key and review recent allows from the same client. |
| P2 | Keep `block-prompt-injection` / `block-jailbreak` enabled in `aiwall.yaml` (or the developer preset) for shared gateways. |
| P2 | For lab-only hosts running adversarial tests, temporarily warn instead of block — document the change. |
| P3 | Tune keyword patterns only with a regression corpus; false positives should be rare on normal developer prose. |

## Close-out

- Confirm no follow-on secret-exfil or agent-tool alerts for the same window.
- Link the audit `request_id`s in the ticket.
- Re-run AIWall-redteam PI-01 / PI-03 if you changed policies.
