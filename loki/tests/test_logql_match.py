#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Mohsen Bah
# SPDX-License-Identifier: Apache-2.0
"""Offline check: each Loki query pack entry matches the expected sample events."""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
PACK = ROOT / "loki" / "queries.json"
SAMPLE_JSONL = ROOT / "validation" / "samples" / "aiwall.audit.v1.sample.jsonl"

# Minimal LogQL fragment we expect after the stream selector.
_FILTER_EQ = re.compile(
    r'\|\s*json\b.*?\|\s*(?P<field>[A-Za-z_][A-Za-z0-9_]*)\s*=\s*"(?P<value>[^"]*)"'
)


def _value_matches(actual, expected) -> bool:
    """Lists mean any-of; dicts support startswith / regex."""
    if isinstance(expected, dict):
        text = "" if actual is None else str(actual)
        if "startswith" in expected:
            return text.startswith(str(expected["startswith"]))
        if "regex" in expected:
            return re.search(str(expected["regex"]), text) is not None
        raise AssertionError(f"unsupported filter dict keys: {sorted(expected)}")
    if isinstance(expected, (list, tuple)):
        return any(str(actual) == str(option) for option in expected)
    return str(actual) == str(expected)


def _event_matches(event: dict, filters: dict) -> bool:
    return all(
        _value_matches(event.get(key), expected) for key, expected in filters.items()
    )


def _logql_declares_filters(logql: str, filters: dict) -> bool:
    """Ensure the published LogQL string encodes the same filters."""
    if "| json" not in logql:
        return False
    declared = {m.group("field"): m.group("value") for m in _FILTER_EQ.finditer(logql)}
    for key, value in filters.items():
        if isinstance(value, dict) and "startswith" in value:
            prefix = str(value["startswith"])
            needle = f'{key}=~"{prefix}.*"'
            if needle not in logql:
                return False
            continue
        if isinstance(value, dict) and "regex" in value:
            needle = f'{key}=~"{value["regex"]}"'
            if needle not in logql:
                return False
            continue
        if isinstance(value, (list, tuple)):
            # A list filter must be published as a regex alternation covering
            # exactly those values, in order: field=~"a|b".
            needle = f'{key}=~"{"|".join(str(v) for v in value)}"'
            if needle not in logql:
                return False
            continue
        if declared.get(key) != str(value):
            # Also accept label-style after json pipeline without capture miss:
            needle = f'{key}="{value}"'
            if needle not in logql:
                return False
    return True


def main() -> int:
    if not PACK.is_file():
        print(f"missing pack: {PACK}", file=sys.stderr)
        return 1
    if not SAMPLE_JSONL.is_file():
        print(f"missing samples: {SAMPLE_JSONL}", file=sys.stderr)
        return 1

    pack = json.loads(PACK.read_text())
    queries = pack.get("queries") or []
    if len(queries) < 4:
        print(f"expected >= 4 queries, found {len(queries)}", file=sys.stderr)
        return 1

    events = [
        json.loads(line)
        for line in SAMPLE_JSONL.read_text().splitlines()
        if line.strip()
    ]
    by_id = {str(e.get("request_id") or ""): e for e in events}

    errors = 0
    for entry in queries:
        qid = entry.get("id") or "<missing-id>"
        filters = entry.get("filters") or {}
        logql = entry.get("logql") or ""
        expect = list(entry.get("expect_request_ids") or [])

        if not qid or not filters or not logql or not expect:
            print(f"FAIL {qid}: incomplete entry", file=sys.stderr)
            errors += 1
            continue

        if not _logql_declares_filters(logql, filters):
            print(
                f"FAIL {qid}: logql does not declare filters {filters}: {logql!r}",
                file=sys.stderr,
            )
            errors += 1
            continue

        hits = sorted(
            str(e.get("request_id") or "")
            for e in events
            if _event_matches(e, filters)
        )
        expected_sorted = sorted(expect)
        if hits != expected_sorted:
            print(
                f"FAIL {qid}: expected {expected_sorted}, got {hits}",
                file=sys.stderr,
            )
            errors += 1
            continue

        for rid in expect:
            if rid not in by_id:
                print(f"FAIL {qid}: sample missing {rid}", file=sys.stderr)
                errors += 1
                break
        else:
            print(f"ok {qid}: {len(hits)} hit(s) {hits}")

    if errors:
        print(f"FAILED: {errors} query(ies)", file=sys.stderr)
        return 1
    print(f"PASS: {len(queries)} Loki queries match the sample corpus")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
