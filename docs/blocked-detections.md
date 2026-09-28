# Blocked detection work (needs AIWall core)

These items were tracked in the long-term plan under Detection Integration.
Prompt-injection and extraction-rate reasons now ship in Community core.

## Prompt injection / jailbreak / meta-prompt — shipped

| ATLAS | Red-team | Status |
|---|---|---|
| AML.T0051 | PI-01 | **Done** — core `injection-detected` + Wazuh **107217** |
| AML.T0054 | PI-02 / DAN | **Done** — safety-bypass framing and DAN-style probes emit `jailbreak-detected` (Wazuh **107218**) |
| AML.T0056 | PI-03 | **Done** — core `jailbreak-detected` + Wazuh **107218** |

See playbook [`prompt-injection-blocked.md`](../playbooks/prompt-injection-blocked.md).

## Model-extraction / high-volume query (AML.T0024) — shipped

Core computes a rolling request/token window (`rate_limits`) and emits
`extraction-rate` on the blocking audit line. Wazuh **107219** / Sigma
`aiwall_extraction_rate` match that reason.

See playbook [`extraction-rate-blocked.md`](../playbooks/extraction-rate-blocked.md)
and AIWall `docs/configuration.md`.

## Remaining product gaps (not SIEM-blocked)

| Item | Notes |
|---|---|
| Multi-tenant / org labels | If core adds org fields to export, extend decoders and dashboards |

## Related

- Bridge: [`validation/redteam_bridge.json`](../validation/redteam_bridge.json)
- Coverage matrix: [`coverage-matrix.md`](coverage-matrix.md)
