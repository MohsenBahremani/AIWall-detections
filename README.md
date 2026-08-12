# AIWall-detections

Detection packs for [AIWall](https://github.com/MohsenBah/AIWall) audit logs: Wazuh, Sigma, Grafana/Loki, playbooks, and MITRE ATLAS mappings.

**Event contract:** `aiwall.audit.v1` JSON Lines — no raw prompts.  
Upstream schema: [AIWall `docs/audit-export.md`](https://github.com/MohsenBah/AIWall/blob/main/docs/audit-export.md).

## Quick start: load rules against AIWall logs

### 1. Export events from AIWall

```bash
curl -OJ "http://127.0.0.1:8080/events/export.jsonl?window_hours=24"
```

Or use the sample corpus while testing:

```bash
cp validation/samples/aiwall.audit.v1.sample.jsonl /tmp/aiwall.audit.jsonl
```

Field reference: [docs/data-sources.md](docs/data-sources.md).

### 2. Pick a pack

| Goal | Path | Docs |
|---|---|---|
| SIEM alerts (Wazuh) | `wazuh/decoders/` + `wazuh/rules/` | [wazuh/README.md](wazuh/README.md) |
| Portable rules (Sigma) | `sigma/rules/*.yml` | [sigma/README.md](sigma/README.md) |
| Dashboards + LogQL | `grafana/` + `loki/queries.json` | [grafana/README.md](grafana/README.md), [loki/README.md](loki/README.md) |

**Wazuh (minimal):**

```bash
sudo cp wazuh/decoders/aiwall_decoders.xml /var/ossec/etc/decoders/
sudo cp wazuh/rules/aiwall_rules.xml /var/ossec/etc/rules/
# point a localfile at your JSONL — see wazuh/README.md
sudo systemctl restart wazuh-manager
```

**Grafana sample stack (no Wazuh required):**

```bash
cd grafana && docker compose up -d
# open http://localhost:3000/d/aiwall-overview
# Explore → paste queries from loki/queries.json
```

**Offline check (CI entrypoint):**

```bash
pip install -r requirements.txt
python3 validation/validate_rules.py
```

### 3. Triage hits

| Alert / reason | Playbook |
|---|---|
| Secret leak / redact | [playbooks/secret-leak-detected.md](playbooks/secret-leak-detected.md) |
| Child / category block | [playbooks/child-safety-block.md](playbooks/child-safety-block.md) |
| Suspicious agent action | [playbooks/suspicious-agent-action.md](playbooks/suspicious-agent-action.md) |

ATLAS mapping for every detection: [docs/coverage-matrix.md](docs/coverage-matrix.md).  
What ships vs what’s next: [docs/detection-roadmap.md](docs/detection-roadmap.md).

## What’s in the box

| Content | Description |
|---|---|
| **Wazuh** | Decoders + rules 100210–100213 (secret, category, cost, daily-limit) |
| **Sigma** | Mirrors of those four alerts (Lucene-convertible) |
| **Grafana** | Overview dashboard (decisions, cost, models, providers) |
| **Loki** | LogQL pack for the same alerts + agent/redact/error triage |
| **Validation** | Sample corpus, expected hits, CI harness |
| **Playbooks** | Triage and response for common events |
| **ATLAS** | Technique coverage matrix |

## Layout

```text
AIWall-detections/
├── docs/           data-sources, ATLAS matrix, detection-roadmap
├── validation/     samples, expected_hits, validate_rules.py
├── wazuh/          decoders, rules, tests
├── sigma/          rules, tests
├── grafana/        dashboard + sample Loki stack
├── loki/           LogQL query pack
├── playbooks/      response guides
└── requirements.txt
```

## Relationship to AIWall

```text
AIWall  ──GET /events/export.jsonl──►  AIWall-detections
         (schema: aiwall.audit.v1)      Wazuh / Sigma / Grafana / Loki
```

This repo **detects and explains** audit outcomes. Enforcement stays in AIWall policies and guardrails.

## Prerequisites

- AIWall exporting `aiwall.audit.v1` JSONL (or the sample file for dry runs)
- Optional: Wazuh manager, Docker (Grafana sample), or a Sigma-compatible SIEM

## Contributing

DCO sign-off on commits. Prefer sample events without real secrets.  
New detection checklist: [docs/detection-roadmap.md](docs/detection-roadmap.md#how-to-propose-a-new-detection).

## License

[Apache License 2.0](LICENSE)
