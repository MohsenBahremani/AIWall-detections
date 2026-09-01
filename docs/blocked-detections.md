# Blocked detection work (needs AIWall core)

These items are tracked in the long-term plan under Detection Integration.
They are **not** shippable as SIEM rules alone — AIWall must emit a stable audit
`reason` (or aggregate metrics) first.

## Prompt injection / jailbreak / meta-prompt

| ATLAS | Red-team | Why blocked |
|---|---|---|
| AML.T0051 | PI-01 | Usually `decision=allow`, `reason=proxied` — nothing for Wazuh to match |
| AML.T0054 | PI-02 | Only adjacent via `category-blocked` when classifiers fire |
| AML.T0056 | PI-03 | Meta-prompt extraction still allows through |

**Unblock when:** core emits a dedicated reason (e.g. `injection-detected` / `jailbreak-detected`) on block or warn. Then add sample JSONL, Wazuh/Sigma/Loki, ATLAS map, playbook, and a `redteam_bridge.json` row (clear `detection_gap`).

## Model-extraction / high-volume query (AML.T0024)

Partial overlap exists with secret-leak rules. A true extraction/rate detection needs **aggregate** signals (requests per profile, tokens over a window), which may require new audit fields or a metrics endpoint — not a single-line Wazuh match.

**Unblock when:** audit/metrics shape is decided and documented in AIWall `docs/audit-export.md`.

## Related

- Bridge gaps: [`validation/redteam_bridge.json`](../validation/redteam_bridge.json) (`detection_gap: true`)
- Coverage matrix: [`coverage-matrix.md`](coverage-matrix.md)
- Red-team baseline: PI-01/PI-03 recorded as inconclusive without allow-path upstream
