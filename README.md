# AIWall-detections

Detection rules, dashboards, and validation content for AIWall security events and AI traffic monitoring.

This repository turns AIWall audit logs into actionable security monitoring: Wazuh rules, Sigma rules, Grafana dashboards, Loki queries, and response playbooks.

## Status

**Placeholder repository.** Content will be added after [AIWall](https://github.com/MohsenBah/AIWall) emits stable audit logs (Phase 6 of the product roadmap).

Do not expect working rules or dashboards here yet.

## Purpose

AIWall generates structured events when it allows, warns, blocks, or redacts AI traffic. This repo packages that telemetry for security teams:

| Content | Description |
|---|---|
| **Wazuh rules** | Decoders and rules for AIWall audit events |
| **Sigma rules** | Portable detection logic for SIEM platforms |
| **Grafana dashboards** | Usage, blocks, secret leaks, and cost panels |
| **Loki queries** | Log queries for AI traffic monitoring |
| **Playbooks** | Response guides for common AI security events |
| **MITRE ATLAS mappings** | Map detections to adversarial ML techniques |

## Planned Structure

```text
AIWall-detections/
├── docs/
│   ├── data-sources.md
│   ├── detection-roadmap.md
│   ├── coverage-matrix.md
│   ├── mitre-atlas-mapping.md
│   └── validation-results.md
├── wazuh/
│   ├── decoders/
│   ├── rules/
│   └── tests/
├── sigma/
│   └── rules/
├── grafana/
│   └── dashboards/
├── loki/
│   └── queries/
├── validation/
│   ├── samples/
│   └── validate_rules.py
└── playbooks/
    ├── secret-leak-detected.md
    ├── child-safety-block.md
    └── suspicious-agent-action.md
```

## Relationship to AIWall

```text
AIWall (core product)
    |
    +-- emits audit events (JSON)
    |
    v
AIWall-detections (this repo)
    |
    +-- Wazuh / Sigma / Grafana / Loki content
    +-- validation samples and playbooks
```

This repo is useful independently once AIWall audit events are documented. You can adapt the rules for other AI gateway deployments that emit similar event schemas.

## Prerequisites

- A running AIWall instance forwarding audit logs to your SIEM or log stack
- Wazuh, Grafana/Loki, or a Sigma-compatible SIEM (depending on which content you use)

Setup instructions will be added when the first detection pack ships.

## Contributing

Contributions welcome once the event schema and first rule pack are published. Use DCO sign-off on commits.

## License

[Apache License 2.0](LICENSE)

## Topics

`ai-security` · `llm-security` · `detection-engineering` · `wazuh` · `grafana` · `loki` · `mitre-atlas` · `siem` · `security-monitoring`
