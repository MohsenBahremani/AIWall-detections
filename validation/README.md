# Validation harness

Canonical sample corpus and offline checks for AIWall-detections.

| Path | Role |
|---|---|
| [`samples/aiwall.audit.v1.sample.jsonl`](samples/aiwall.audit.v1.sample.jsonl) | Mixed `aiwall.audit.v1` events (fake secrets only) |
| [`expected_hits.json`](expected_hits.json) | Per-`request_id` expectations for Wazuh / Sigma / Loki |
| [`validate_rules.py`](validate_rules.py) | CI entrypoint — corpus + hits matrix + pack tests |

`validate_rules.py` also checks that every playbook referenced from the README exists, that the ATLAS map in `docs/atlas-mapping.json` covers each detection, and that the README and roadmap still mention the rule ids they claim to ship.

## Run

From the repo root:

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
python3 validation/validate_rules.py
```

Matrix-only (skip pack scripts):

```bash
python3 validation/validate_rules.py --skip-pack-tests
```

GitHub Actions runs the same command on every push/PR to `main`.
