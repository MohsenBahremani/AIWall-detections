#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Mohsen Bah
# SPDX-License-Identifier: Apache-2.0
"""Offline check: sample events map to the expected Wazuh rule ids."""

from __future__ import annotations

import json
import re
import sys
import xml.etree.ElementTree as ET
from dataclasses import dataclass
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
RULES_XML = ROOT / "wazuh" / "rules" / "aiwall_rules.xml"
SAMPLE_JSONL = ROOT / "validation" / "samples" / "aiwall.audit.v1.sample.jsonl"

# request_id -> expected firing alert rule id (not the level-0 parent)
EXPECTED: dict[str, int] = {
    "req-secret-001": 100210,
    "req-policy-001": 100211,
    "req-cost-001": 100212,
    "req-limit-001": 100213,
}


@dataclass(frozen=True)
class FieldMatch:
    name: str
    pattern: re.Pattern[str]


@dataclass(frozen=True)
class AlertRule:
    rule_id: int
    level: int
    fields: tuple[FieldMatch, ...]
    description: str


def _load_alert_rules(path: Path) -> list[AlertRule]:
    raw = path.read_text()
    tree = ET.fromstring(f"<rules>{raw}</rules>")
    rules: list[AlertRule] = []
    for group in tree.findall("group"):
        for rule in group.findall("rule"):
            level = int(rule.get("level", "0"))
            if level <= 0:
                continue
            rule_id = int(rule.get("id", "0"))
            fields: list[FieldMatch] = []
            for field in rule.findall("field"):
                name = field.get("name")
                if not name or field.text is None:
                    continue
                fields.append(FieldMatch(name=name, pattern=re.compile(field.text)))
            description = (rule.findtext("description") or "").strip()
            if not fields:
                raise AssertionError(f"rule {rule_id} has no <field> conditions")
            rules.append(
                AlertRule(
                    rule_id=rule_id,
                    level=level,
                    fields=tuple(fields),
                    description=description,
                )
            )
    if len(rules) < 4:
        raise AssertionError(f"expected at least 4 alert rules, found {len(rules)}")
    return rules


def _matches(rule: AlertRule, event: dict) -> bool:
    for field in rule.fields:
        value = event.get(field.name)
        text = "" if value is None else str(value)
        if field.pattern.search(text) is None:
            return False
    return True


def main() -> int:
    if not RULES_XML.is_file():
        print(f"missing rules: {RULES_XML}", file=sys.stderr)
        return 1
    if not SAMPLE_JSONL.is_file():
        print(f"missing samples: {SAMPLE_JSONL}", file=sys.stderr)
        return 1

    rules = _load_alert_rules(RULES_XML)
    by_id = {rule.rule_id: rule for rule in rules}
    for rule_id in EXPECTED.values():
        if rule_id not in by_id:
            print(f"missing rule id {rule_id} in {RULES_XML}", file=sys.stderr)
            return 1

    lines = [line for line in SAMPLE_JSONL.read_text().splitlines() if line.strip()]
    fired: dict[str, list[int]] = {}
    for line in lines:
        event = json.loads(line)
        request_id = str(event.get("request_id") or "")
        hits = [rule.rule_id for rule in rules if _matches(rule, event)]
        fired[request_id] = hits

    errors = 0
    for request_id, rule_id in EXPECTED.items():
        hits = fired.get(request_id, [])
        if hits != [rule_id]:
            print(
                f"FAIL {request_id}: expected [{rule_id}], got {hits}",
                file=sys.stderr,
            )
            errors += 1
        else:
            print(f"ok {request_id} -> rule {rule_id} ({by_id[rule_id].description})")

    for request_id, hits in fired.items():
        if request_id in EXPECTED:
            continue
        if hits:
            print(
                f"FAIL {request_id}: unexpected alert rules {hits}",
                file=sys.stderr,
            )
            errors += 1
        else:
            print(f"ok {request_id} -> no Phase 6.3 alert (as expected)")

    if errors:
        print(f"FAILED: {errors} mismatch(es)", file=sys.stderr)
        return 1
    print(f"PASS: {len(EXPECTED)} alert rules fire on the matching sample events")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
