# Blocked detection work (needs AIWall core)

These items are tracked in the long-term plan under Detection Integration.
They are **not** shippable as SIEM rules alone — AIWall must emit a stable audit
`reason` (or aggregate metrics) first.

## Prompt injection / jailbreak / meta-prompt — shipped

| ATLAS | Red-team | Status |
|---|---|---|
| AML.T0051 | PI-01 | **Done** — core `injection-detected` + Wazuh **107217** |
| AML.T0054 | PI-02 / DAN | **Done** for dedicated jailbreak reason; PI-02 still may use `category-blocked` when family classifiers fire |
| AML.T0056 | PI-03 | **Done** — core `jailbreak-detected` + Wazuh **107218** |

See playbook [`prompt-injection-blocked.md`](../playbooks/prompt-injection-blocked.md).

## Model-extraction / high-volume query (AML.T0024)

Partial overlap exists with secret-leak rules. A true extraction/rate detection needs **aggregate** signals (requests per profile, tokens over a window), which may require new audit fields or a metrics endpoint — not a single-line Wazuh match.

**Unblock when:** audit/metrics shape is decided and documented in AIWall `docs/audit-export.md`.

## Related

- Bridge gaps: [`validation/redteam_bridge.json`](../validation/redteam_bridge.json) (`detection_gap: true`)
- Coverage matrix: [`coverage-matrix.md`](coverage-matrix.md)
- Red-team baseline: PI-01/PI-03 now map to sample lines when policies are enabled
