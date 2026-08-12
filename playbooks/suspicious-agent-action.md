# Playbook: Suspicious agent action

**Trigger:** An AI **agent** tool call (shell, file access, or similar) was warned, blocked, or denied after human approval — indicating risky autonomous behavior.

| Signal | Value |
|---|---|
| Audit `decision` | `warn`, `block`, or `block` with approval denial |
| Audit `reason` | e.g. `shell risk …`, `approval-denied`, `sensitive-file-access:…` |
| Audit `matched_rule_ids` | e.g. `rm-rf-root`, `sudo`, `curl-pipe-shell` |
| Audit `policy_id` | e.g. `agent-shell-require-approval`, `agent-shell-warn` |
| Control panel | `/agents` — pending approvals + agent action log |
| Loki | `aiwall_agent_approval_denied` (denials); also filter `matched_rule_ids` / reasons in Explore |
| ATLAS | [AML.T0050](https://atlas.mitre.org/) Command and Scripting Interpreter; AML.T0053 LLM Plugin Compromise |
| Sample | `req-agent-001` (approval denied), `req-warn-001` (shell warn) |

Upstream behavior: [AIWall agent-guardrails.md](https://github.com/MohsenBah/AIWall/blob/main/docs/agent-guardrails.md).

## Triage (5–20 min)

1. Open **`/agents`** (or export JSONL) and locate the `request_id` / action row: tool name, command or path, risk score, decision.
2. Classify severity:
   - **Warn** — proceeded; treat as telemetry unless volume spikes
   - **Block** — stopped before execution (or before provider saw the tool result path, depending on client design)
   - **Approval denied / timeout** — human or policy refused a high-risk hold
3. Answer: was this **expected** operator behavior (admin agent) or an unexpected client/model?
4. Inspect the command/path **without** re-running it. Look for `rm -rf /`, pipe-to-shell, SSH keys under `~/.ssh`, cloud credential files, etc.
5. Correlate nearby events: secret scanner hits, other tool calls from the same session/profile, prompt-injection style follow-ups.

## Response

| Priority | Action |
|---|---|
| P1 | If a **destructive or exfil-style** command was **approved or only warned**, assume the host may be impacted: isolate the agent host, check process/file integrity, rotate credentials that path could read. |
| P1 | Disable or tighten `agent_guardrails` thresholds for that environment (`require_approval_above` / `block_above`) until reviewed. |
| P2 | Rotate the **client API key** used by the agent if the agent may be following untrusted instructions (indirect prompt injection). |
| P2 | Review approval history on `/agents`: who approved what, and whether timeouts are being abused to retry. |
| P3 | Add or adjust shell/file rules if a novel pattern slipped through as low score. |

## Containment checklist

- [ ] Risky tool path identified (shell vs file vs generic tool)
- [ ] Decision path understood (warn / block / approval)
- [ ] Host and secrets checked if execution may have occurred
- [ ] Agent key / guardrail config adjusted
- [ ] Sample `request_id` retained for detection tuning / red-team regression

## False positives

- Lab or homelab agents intentionally testing guardrails
- Legitimate admin automation that trips `sudo` warn (~score 55) — consider allowlisting specific wrappers, not disabling guardrails globally
- Approval timeouts when an operator was away (reason may differ from explicit deny — still investigate the proposed command)

## Related

- Coverage: [docs/coverage-matrix.md](../docs/coverage-matrix.md)
- Approvals API / hold behavior: AIWall docs `agent-guardrails.md`
- Sibling playbooks: [secret-leak-detected.md](secret-leak-detected.md), [child-safety-block.md](child-safety-block.md)
