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

# filename stem -> expected sample request_ids that should match
EXPECTED_HITS: dict[str, set[str]] = {
    "aiwall_secret_leak_blocked": {"req-secret-001"},
    "aiwall_policy_block": {"req-policy-001"},
    "aiwall_cost_threshold": {"req-cost-001", "req-cost-002"},
    "aiwall_daily_limit": {"req-limit-001"},
}


def _value_matches(actual, expected) -> bool:
    """A list of expected values means "any of", matching Sigma list semantics."""
    if isinstance(expected, (list, tuple)):
        return any(str(actual) == str(option) for option in expected)
    return str(actual) == str(expected)


def _event_matches_selection(event: dict, selection: dict) -> bool:
    return all(
        _value_matches(event.get(key), expected) for key, expected in selection.items()
    )


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
        expected_ids = EXPECTED_HITS.get(stem)
        if expected_ids is None:
            print(f"FAIL {path.name}: no EXPECTED_HITS entry", file=sys.stderr)
            errors += 1
            continue
        missing = sorted(rid for rid in expected_ids if rid not in events)
        if missing:
            print(f"FAIL {path.name}: samples {missing} missing", file=sys.stderr)
            errors += 1
            continue

        hits = {
            rid
            for rid, event in events.items()
            if _event_matches_selection(event, selection)
        }
        if hits != expected_ids:
            print(
                f"FAIL {path.name}: expected {sorted(expected_ids)}, got {sorted(hits)}",
                file=sys.stderr,
            )
            errors += 1
            continue

        print(f"ok {path.name}: Lucene={queries[0]!r} hits={sorted(hits)}")

    if errors:
        print(f"FAILED: {errors} rule(s)", file=sys.stderr)
        return 1
    print(f"PASS: {len(rule_files)} Sigma rules validated and converted to Lucene")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
