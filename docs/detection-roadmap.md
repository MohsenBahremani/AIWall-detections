# Detection roadmap

Where AIWall-detections is going next, and what already ships for operators.

## Shipped (usable today)

| Area | What you get |
|---|---|
| **Contract** | `aiwall.audit.v1` JSONL from AIWall (`GET /events/export.jsonl`) |
| **Samples** | `validation/samples/aiwall.audit.v1.sample.jsonl` + expected hits |
| **Wazuh** | Decoders + rules 107210–107215 (secret, category, cost, daily-limit, agent deny, shell-risk warn) |
| **Sigma** | Six mirrors, Lucene-convertible |
| **Grafana / Loki** | Overview dashboard + sample compose stack + LogQL pack |
| **ATLAS** | Every detection mapped (`docs/coverage-matrix.md`) |
| **Red team bridge** | Technique → sample → rule map (`docs/redteam-bridge.md`) |
| **Alert routing** | ntfy / webhook examples by Wazuh rule id (`docs/alert-routing.md`) |
| **E2E lab script** | `scripts/validate_export.sh` (+ `check_export_hits.py`) |
| **Playbooks** | Secret leak, child safety, suspicious agent action |
| **CI** | `validation/validate_rules.py` on push/PR |

Follow the [README quick start](README.md#quick-start-load-rules-against-aiwall-logs) to wire logs once.

## Near-term candidates

Prioritized for Community follow-ups (issue-sized):

1. **Multi-tenant / org labels** — if AIWall adds org fields to audit export, extend decoders and dashboards.

Blocked on core (see [`blocked-detections.md`](blocked-detections.md)): prompt-injection / jailbreak reasons; model-extraction / rate metrics.

## End-to-end lab check

```bash
# Sample corpus + packs
python3 validation/validate_rules.py

# Live export (optional: --with-regression if ../AIWall-redteam is present)
./scripts/validate_export.sh
./scripts/validate_export.sh --file validation/samples/aiwall.audit.v1.sample.jsonl \
  --require-reasons secret-detected approval-denied
```


## Alignment with AIWall Red Team

[AIWall-redteam](https://github.com/MohsenBahremani/AIWall-redteam) ships the attack catalog and must-block regression suite. The bridge in this repo maps those techniques to sample audit lines and SIEM rules:

- Machine-readable: [`validation/redteam_bridge.json`](../validation/redteam_bridge.json)
- Operator doc: [`docs/redteam-bridge.md`](redteam-bridge.md)
- Prefer regression: campaign → expected audit reason → detection fire

Gaps (PI-01, PI-03, AT-02, dedicated jailbreak) are listed in the bridge with `detection_gap: true`.

## How to propose a new detection

1. Capture or craft an `aiwall.audit.v1` sample line (fake secrets only).
2. Add expectations to `validation/expected_hits.json`.
3. Implement Wazuh and/or Sigma and/or Loki entries; map ATLAS in `docs/atlas-mapping.json`.
4. If the sample comes from a red-team technique, add a row to `validation/redteam_bridge.json`.
5. Link a playbook section or new playbook if operators need triage steps.
6. Run `python3 validation/validate_rules.py` and open a PR.

## Out of scope (for now)

- Parsing raw prompts (export is privacy-safe by design)
- Vendor-specific cloud SIEM consoles beyond Sigma conversion targets
- Replacing AIWall’s own policy engine — this repo **detects** outcomes, it does not enforce them
