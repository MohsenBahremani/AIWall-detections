# Shipped detection work (Community core)

These items were tracked in the long-term plan under Detection Integration.
They now ship in Community core and in this pack.

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

## Sensitive-file access (AT-02) — shipped

Agent file tools that hit SSH keys, cloud creds, and similar paths emit
`sensitive-file-access:<rule_id>`. Wazuh **107220** / Sigma
`aiwall_sensitive_file_access` match the prefix.

## Output-secret DLP (SE-03 reply path) — shipped

Secrets in **model replies** emit `output-secret-detected` when
`output.contains_secret` is configured. Wazuh **107221** / Sigma
`aiwall_output_secret_blocked`.

## Remaining follow-ups (not SIEM-blocked)

| Item | Notes |
|---|---|
| Multi-tenant / org labels | If core adds org fields to export, extend decoders and dashboards |

## Related

- Bridge: [`validation/redteam_bridge.json`](../validation/redteam_bridge.json)
- Coverage matrix: [`coverage-matrix.md`](coverage-matrix.md)
