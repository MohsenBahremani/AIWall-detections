# Response playbooks

Operator guides for common AIWall security events. Each playbook covers **triage** and **response** using `aiwall.audit.v1` fields (no raw prompts in the export).

| Playbook | When to use |
|---|---|
| [secret-leak-detected.md](secret-leak-detected.md) | `secret-detected` / `secret-redacted` |
| [child-safety-block.md](child-safety-block.md) | `category-blocked` (family / child policy) |
| [suspicious-agent-action.md](suspicious-agent-action.md) | Agent shell/file warn, block, or approval denial |

Detections that fire these alerts: [docs/coverage-matrix.md](../docs/coverage-matrix.md).  
How to pull events: [docs/data-sources.md](../docs/data-sources.md).
