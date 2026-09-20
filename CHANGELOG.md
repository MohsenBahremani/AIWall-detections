# Changelog

## [Unreleased]

### Added

- Wazuh rules **107217** / **107218** for `injection-detected` and `jailbreak-detected`, with Sigma, Loki, sample corpus, ATLAS map, and playbook.
- Closed audit-reason contract entries for prompt-injection / jailbreak (mirrors core).

### Changed

- **Breaking for existing operators:** Wazuh rules renumbered into the `1072xx` range (parents `107200`/`107201`, alerts `107210`–`107218`). Re-copy `wazuh/rules/aiwall_rules.xml` and update any alerting keyed to the old ids.

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
