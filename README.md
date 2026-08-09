# AIWall-detections

Detection rules, dashboards, and validation content for AIWall security events.

Turns AIWall audit logs into monitoring content: Wazuh, Sigma, Grafana, Loki, and playbooks.

## Where things stand

Schema freeze is done: **`aiwall.audit.v1`** JSON Lines from AIWall.

- [docs/data-sources.md](docs/data-sources.md) — how to pull events and what fields mean
- [validation/samples/aiwall.audit.v1.sample.jsonl](validation/samples/aiwall.audit.v1.sample.jsonl) — sample corpus
- [wazuh/decoders/aiwall_decoders.xml](wazuh/decoders/aiwall_decoders.xml) — Wazuh JSON decoders (named fields)
- [wazuh/rules/aiwall_rules.xml](wazuh/rules/aiwall_rules.xml) — secret / policy / cost / daily-limit alerts
- [sigma/rules/](sigma/rules/) — Sigma mirrors of those alerts (Lucene-convertible)
- [grafana/](grafana/) — Overview dashboard + sample Loki stack
- [loki/](loki/) — LogQL query pack (secret / policy / cost / daily-limit + triage)
- [validation/](validation/) — sample corpus, expected hits, `validate_rules.py` (CI)

Still ahead: MITRE ATLAS mapping, playbooks, detection roadmap.

## Purpose

| Content | Description |
|---|---|
| **Wazuh rules** | Decoders and rules for AIWall audit events |
| **Sigma rules** | Portable detection logic for SIEM platforms |
| **Grafana dashboards** | Usage, blocks, secret leaks, and cost panels |
| **Loki queries** | Log queries for AI traffic monitoring |
| **Playbooks** | Response guides for common AI security events |
| **MITRE ATLAS mappings** | Map detections to adversarial ML techniques |

## Layout

```text
AIWall-detections/
├── docs/
│   └── data-sources.md
├── validation/
│   ├── samples/
│   ├── expected_hits.json
│   ├── validate_rules.py
│   └── README.md
├── wazuh/
│   ├── decoders/
│   ├── rules/
│   ├── tests/
│   └── README.md
├── sigma/
│   ├── rules/
│   ├── tests/
│   └── README.md
├── grafana/
│   ├── dashboards/
│   ├── provisioning/
│   ├── tests/
│   └── docker-compose.yml
├── loki/
│   ├── queries.json
│   ├── tests/
│   └── README.md
├── requirements.txt
└── (playbooks / ATLAS — coming next)
```

## Relationship to AIWall

```text
AIWall
  └── GET /events/export.jsonl   (schema: aiwall.audit.v1)
         │
         v
AIWall-detections
  └── Wazuh / Sigma / Grafana / Loki + samples
```

Upstream schema docs: [AIWall docs/audit-export.md](https://github.com/MohsenBah/AIWall/blob/main/docs/audit-export.md).

## Validate

```bash
pip install -r requirements.txt
python3 validation/validate_rules.py
```

See [validation/README.md](validation/README.md). GitHub Actions runs this on `main` pushes and PRs.

## Prerequisites

- AIWall exporting `aiwall.audit.v1` JSONL
- Wazuh, Grafana/Loki, or a Sigma-compatible SIEM (depending on which pack you use)

## Contributing

DCO sign-off on commits. Prefer sample events without real secrets.

## License

[Apache License 2.0](LICENSE)
