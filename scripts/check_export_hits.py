#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Mohsen Bah
# SPDX-License-Identifier: Apache-2.0
"""Score a live (or saved) aiwall.audit.v1 JSONL export against Wazuh alert rules.

Usage::

    python3 scripts/check_export_hits.py /tmp/aiwall.audit.jsonl
    python3 scripts/check_export_hits.py --require-reasons secret-detected approval-denied
"""

from __future__ import annotations

import argparse
import json
import re
import sys
import xml.etree.ElementTree as ET
from dataclasses import dataclass
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
RULES_XML = ROOT / "wazuh" / "rules" / "aiwall_rules.xml"


@dataclass(frozen=True)
class FieldMatch:
    name: str
    pattern: re.Pattern[str]


@dataclass(frozen=True)
class AlertRule:
    rule_id: int
    description: str
    fields: tuple[FieldMatch, ...]


def _load_alert_rules(path: Path) -> list[AlertRule]:
    tree = ET.fromstring(f"<rules>{path.read_text()}</rules>")
    rules: list[AlertRule] = []
    for group in tree.findall("group"):
        for rule in group.findall("rule"):
            if int(rule.get("level", "0")) <= 0:
                continue
            fields: list[FieldMatch] = []
            for field in rule.findall("field"):
                name = field.get("name")
                if not name or field.text is None:
                    continue
                fields.append(FieldMatch(name=name, pattern=re.compile(field.text)))
            rules.append(
                AlertRule(
                    rule_id=int(rule.get("id", "0")),
                    description=(rule.findtext("description") or "").strip(),
                    fields=tuple(fields),
                )
            )
    return rules


def _matches(rule: AlertRule, event: dict) -> bool:
    for field in rule.fields:
        value = event.get(field.name)
        text = "" if value is None else str(value)
        if field.pattern.search(text) is None:
            return False
    return True


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "export_jsonl",
        type=Path,
        help="Path to aiwall.audit.v1 JSON Lines (live export or sample)",
    )
    parser.add_argument(
        "--require-reasons",
        nargs="*",
        default=[],
        help="Fail unless each listed reason prefix/exact value appears and fires a rule",
    )
    args = parser.parse_args(argv)

    if not args.export_jsonl.is_file():
        print(f"missing export: {args.export_jsonl}", file=sys.stderr)
        return 1
    if not RULES_XML.is_file():
        print(f"missing rules: {RULES_XML}", file=sys.stderr)
        return 1

    rules = _load_alert_rules(RULES_XML)
    events: list[dict] = []
    for line_no, line in enumerate(args.export_jsonl.read_text().splitlines(), start=1):
        if not line.strip():
            continue
        try:
            event = json.loads(line)
        except json.JSONDecodeError as exc:
            print(f"line {line_no}: invalid JSON: {exc}", file=sys.stderr)
            return 1
        if event.get("schema") != "aiwall.audit.v1":
            print(f"line {line_no}: expected schema aiwall.audit.v1", file=sys.stderr)
            return 1
        events.append(event)

    if not events:
        print("export is empty", file=sys.stderr)
        return 1

    fired_reasons: set[str] = set()
    hits = 0
    for event in events:
        reason = str(event.get("reason") or "")
        matching = [r for r in rules if _matches(r, event)]
        if not matching:
            continue
        hits += 1
        fired_reasons.add(reason)
        rid = event.get("request_id")
        ids = ",".join(str(r.rule_id) for r in matching)
        print(f"hit request_id={rid} reason={reason!r} wazuh=[{ids}]")

    print(f"scored {len(events)} events → {hits} detection hit(s)")

    missing: list[str] = []
    for required in args.require_reasons:
        if not any(
            reason == required or reason.startswith(required) for reason in fired_reasons
        ):
            # Also accept if an event has the reason even when no rule matched
            # (caller asked for reason presence with a firing rule).
            missing.append(required)

    if missing:
        print(
            f"FAIL: required reasons not observed with a Wazuh hit: {missing}",
            file=sys.stderr,
        )
        return 1

    if args.require_reasons:
        print(f"ok required reasons present: {args.require_reasons}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
