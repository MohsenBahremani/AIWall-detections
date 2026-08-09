#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Mohsen Bah
# SPDX-License-Identifier: Apache-2.0
"""Validate Sigma rules and convert them to Elasticsearch Lucene queries."""

from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
RULES_DIR = ROOT / "sigma" / "rules"
SAMPLE_JSONL = ROOT / "validation" / "samples" / "aiwall.audit.v1.sample.jsonl"

# filename stem -> expected sample request_id that should match
EXPECTED_HITS: dict[str, str] = {
    "aiwall_secret_leak_blocked": "req-secret-001",
    "aiwall_policy_block": "req-policy-001",
    "aiwall_cost_threshold": "req-cost-001",
    "aiwall_daily_limit": "req-limit-001",
}


def _event_matches_selection(event: dict, selection: dict) -> bool:
    for key, expected in selection.items():
        actual = event.get(key)
        if str(actual) != str(expected):
            return False
    return True


def main() -> int:
    try:
        from sigma.rule import SigmaRule
        from sigma.backends.elasticsearch import LuceneBackend
    except ImportError:
        print(
            "Install deps: pip install -r requirements.txt "
            "(needs pysigma + pysigma-backend-elasticsearch)",
            file=sys.stderr,
        )
        return 1

    if not RULES_DIR.is_dir():
        print(f"missing rules dir: {RULES_DIR}", file=sys.stderr)
        return 1
    if not SAMPLE_JSONL.is_file():
        print(f"missing samples: {SAMPLE_JSONL}", file=sys.stderr)
        return 1

    events = {
        str(event["request_id"]): event
        for line in SAMPLE_JSONL.read_text().splitlines()
        if line.strip()
        for event in [json.loads(line)]
    }

    backend = LuceneBackend()
    rule_files = sorted(RULES_DIR.glob("*.yml"))
    if len(rule_files) < 4:
        print(f"expected >= 4 rules, found {len(rule_files)}", file=sys.stderr)
        return 1

    errors = 0
    for path in rule_files:
        stem = path.stem
        try:
            rule = SigmaRule.from_yaml(path.read_text())
        except Exception as exc:  # noqa: BLE001 - report parse errors clearly
            print(f"FAIL {path.name}: parse error: {exc}", file=sys.stderr)
            errors += 1
            continue

        try:
            queries = backend.convert_rule(rule)
        except Exception as exc:  # noqa: BLE001
            print(f"FAIL {path.name}: Lucene convert error: {exc}", file=sys.stderr)
            errors += 1
            continue

        if not queries or not all(isinstance(q, str) and q.strip() for q in queries):
            print(f"FAIL {path.name}: empty Lucene conversion", file=sys.stderr)
            errors += 1
            continue

        # Simple field-equality check against sample (mirrors detection.selection).
        import yaml

        raw = yaml.safe_load(path.read_text())
        selection = raw["detection"]["selection"]
        expected_id = EXPECTED_HITS.get(stem)
        if expected_id is None:
            print(f"FAIL {path.name}: no EXPECTED_HITS entry", file=sys.stderr)
            errors += 1
            continue
        target = events.get(expected_id)
        if target is None:
            print(f"FAIL {path.name}: sample {expected_id} missing", file=sys.stderr)
            errors += 1
            continue
        if not _event_matches_selection(target, selection):
            print(
                f"FAIL {path.name}: selection does not match sample {expected_id}",
                file=sys.stderr,
            )
            errors += 1
            continue

        # Non-target samples should not match this selection.
        false_hits = [
            rid
            for rid, event in events.items()
            if rid != expected_id and _event_matches_selection(event, selection)
        ]
        if false_hits:
            print(
                f"FAIL {path.name}: unexpected matches {false_hits}",
                file=sys.stderr,
            )
            errors += 1
            continue

        print(f"ok {path.name}: Lucene={queries[0]!r} hit={expected_id}")

    if errors:
        print(f"FAILED: {errors} rule(s)", file=sys.stderr)
        return 1
    print(f"PASS: {len(rule_files)} Sigma rules validated and converted to Lucene")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
