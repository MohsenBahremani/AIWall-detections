# Changelog

## [Unreleased]

### Added

- Wazuh rules **107217** / **107218** for `injection-detected` and `jailbreak-detected`, with Sigma, Loki, sample corpus, ATLAS map, and playbook.
- Wazuh rule **107219** for `extraction-rate` (AML.T0024), with Sigma, Loki, sample `req-extract-001`, and playbook.
- Wazuh rule **107220** for `sensitive-file-access:*` (AT-02), with Sigma, Loki, and sample `req-sensitive-file-001`.
- Wazuh rule **107221** for `output-secret-detected` (SE-03 output DLP), with Sigma, Loki, and sample `req-output-secret-001`.
- Closed audit-reason contract entries for prompt-injection / jailbreak (mirrors core).

### Changed

- Operator docs now list Wazuh **107210–107221**, the full Sigma and Loki packs, and the injection / extraction-rate playbooks.
- **Breaking for existing operators:** Wazuh rules renumbered into the `1072xx` range (parents `107200`/`107201`, alerts `107210`–`107221`). Re-copy `wazuh/rules/aiwall_rules.xml` and update any alerting keyed to the old ids.

### Fixed

- JSONL parent rule matching in the Wazuh decoders.
- `docs/detection-roadmap.md` advertised rules `107210`–`107215`, omitting `107216` (cost-budget blocks), and its quick-start link resolved to a nonexistent `docs/README.md`.

## [0.1.0] - 2026-08-27

### Added

- Wazuh, Sigma, and Loki detection packs for AIWall audit export.
- Sample corpus, validation harness, ATLAS mapping, and red-team bridge.
- Published audit reason contract (`validation/audit_reasons.json`).

### Compatibility

- Requires AIWall Community `>= 0.1.0` emitting `aiwall.audit.v1` with closed `reason` values documented in upstream `docs/audit-export.md`.
