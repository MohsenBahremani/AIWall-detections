# Detection roadmap

Where AIWall-detections is going next, and what already ships for operators.

## Shipped (usable today)

| Area | What you get |
|---|---|
| **Contract** | `aiwall.audit.v1` JSONL from AIWall (`GET /events/export.jsonl`) |
| **Samples** | `validation/samples/aiwall.audit.v1.sample.jsonl` + expected hits |
| **Wazuh** | Decoders + rules 100210–100213 (secret, category, cost, daily-limit) |
| **Sigma** | Four mirrors, Lucene-convertible |
| **Grafana / Loki** | Overview dashboard + sample compose stack + LogQL pack |
| **ATLAS** | Every detection mapped (`docs/coverage-matrix.md`) |
| **Playbooks** | Secret leak, child safety, suspicious agent action |
| **CI** | `validation/validate_rules.py` on push/PR |

Follow the [README quick start](README.md#quick-start-load-rules-against-aiwall-logs) to wire logs once.

## Near-term candidates

Prioritized for Community follow-ups (issue-sized):

1. **Prompt-injection / jailbreak signals** — dedicated rules for AML.T0051 / AML.T0054 (today only adjacent agent warns).
2. **Agent-action Wazuh/Sigma alerts** — promote `approval-denied` / high shell risk from Loki-only to full SIEM packs.
3. **Model-extraction / high-volume query** — AML.T0024 style rate/anomaly detections on audit metrics.
4. **Alert routing examples** — ntfy / webhook snippets keyed off Wazuh rule ids or Loki alerts.
5. **Multi-tenant / org labels** — if AIWall adds org fields to audit export, extend decoders and dashboards.

## Alignment with AIWall Red Team (Phase 7)

When [AIWall-redteam](https://github.com/MohsenBah/AIWall-redteam) publishes attack catalogs and campaigns:

- Add sample JSONL lines for each successful control hit.
- Extend `expected_hits.json` and ATLAS gaps listed in `docs/coverage-matrix.md`.
- Prefer regression: campaign → expected audit reason → detection fire.

## How to propose a new detection

1. Capture or craft an `aiwall.audit.v1` sample line (fake secrets only).
2. Add expectations to `validation/expected_hits.json`.
3. Implement Wazuh and/or Sigma and/or Loki entries; map ATLAS in `docs/atlas-mapping.json`.
4. Link a playbook section or new playbook if operators need triage steps.
5. Run `python3 validation/validate_rules.py` and open a PR.

## Out of scope (for now)

- Parsing raw prompts (export is privacy-safe by design)
- Vendor-specific cloud SIEM consoles beyond Sigma conversion targets
- Replacing AIWall’s own policy engine — this repo **detects** outcomes, it does not enforce them
