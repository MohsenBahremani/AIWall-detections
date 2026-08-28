# Changelog

## [0.1.0] - 2026-08-27

### Added

- Wazuh, Sigma, and Loki detection packs for AIWall audit export.
- Sample corpus, validation harness, ATLAS mapping, and red-team bridge.
- Published audit reason contract (`validation/audit_reasons.json`).

### Compatibility

- Requires AIWall Community `>= 0.1.0` emitting `aiwall.audit.v1` with closed `reason` values documented in upstream `docs/audit-export.md`.
