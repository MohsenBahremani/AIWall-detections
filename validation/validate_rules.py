#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Mohsen Bah
# SPDX-License-Identifier: Apache-2.0
"""Run AIWall-detections rules against the sample corpus and assert expected hits.

Usage (from repo root)::

    python3 validation/validate_rules.py
    python3 validation/validate_rules.py --skip-pack-tests
"""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
import xml.etree.ElementTree as ET
from dataclasses import dataclass
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
EXPECTED_PATH = Path(__file__).resolve().parent / "expected_hits.json"
SAMPLE_JSONL = Path(__file__).resolve().parent / "samples" / "aiwall.audit.v1.sample.jsonl"
WAZUH_RULES = ROOT / "wazuh" / "rules" / "aiwall_rules.xml"
SIGMA_DIR = ROOT / "sigma" / "rules"
LOKI_PACK = ROOT / "loki" / "queries.json"

PACK_TESTS = (
    ROOT / "wazuh" / "tests" / "test_decoder_fields.py",
    ROOT / "wazuh" / "tests" / "test_rules_match.py",
    ROOT / "sigma" / "tests" / "test_sigma_convert.py",
    ROOT / "loki" / "tests" / "test_logql_match.py",
    ROOT / "grafana" / "tests" / "test_dashboard.py",
)

REQUIRED_SAMPLE_FIELDS = (
    "schema",
    "request_id",
    "provider",
    "model",
    "decision",
    "reason",
)


@dataclass(frozen=True)
class FieldMatch:
    name: str
    pattern: re.Pattern[str]


@dataclass(frozen=True)
class AlertRule:
    rule_id: int
    fields: tuple[FieldMatch, ...]


def _load_events(path: Path) -> list[dict]:
    events: list[dict] = []
    for line_no, line in enumerate(path.read_text().splitlines(), start=1):
        if not line.strip():
            continue
        try:
            event = json.loads(line)
        except json.JSONDecodeError as exc:
            raise AssertionError(f"{path}:{line_no}: invalid JSON: {exc}") from exc
        events.append(event)
    return events


def _load_wazuh_alerts(path: Path) -> dict[int, AlertRule]:
    tree = ET.fromstring(f"<rules>{path.read_text()}</rules>")
    rules: dict[int, AlertRule] = {}
    for group in tree.findall("group"):
        for rule in group.findall("rule"):
            if int(rule.get("level", "0")) <= 0:
                continue
            rule_id = int(rule.get("id", "0"))
            fields: list[FieldMatch] = []
            for field in rule.findall("field"):
                name = field.get("name")
                if not name or field.text is None:
                    continue
                fields.append(FieldMatch(name=name, pattern=re.compile(field.text)))
            rules[rule_id] = AlertRule(rule_id=rule_id, fields=tuple(fields))
    return rules


def _wazuh_matches(rule: AlertRule, event: dict) -> bool:
    for field in rule.fields:
        value = event.get(field.name)
        text = "" if value is None else str(value)
        if field.pattern.search(text) is None:
            return False
    return True


def _load_sigma_selections() -> dict[str, dict]:
    try:
        import yaml
    except ImportError as exc:
        raise AssertionError(
            "PyYAML required for Sigma checks (pip install -r requirements.txt)"
        ) from exc

    out: dict[str, dict] = {}
    for path in sorted(SIGMA_DIR.glob("*.yml")):
        raw = yaml.safe_load(path.read_text())
        selection = (raw.get("detection") or {}).get("selection")
        if not isinstance(selection, dict):
            raise AssertionError(f"{path.name}: missing detection.selection")
        out[path.stem] = selection
    return out


def _sigma_matches(selection: dict, event: dict) -> bool:
    for key, expected in selection.items():
        if str(event.get(key)) != str(expected):
            return False
    return True


def _loki_matches(filters: dict, event: dict) -> bool:
    for key, expected in filters.items():
        if str(event.get(key)) != str(expected):
            return False
    return True


def check_corpus(events: list[dict]) -> list[str]:
    errors: list[str] = []
    seen: set[str] = set()
    for i, event in enumerate(events, start=1):
        if event.get("schema") != "aiwall.audit.v1":
            errors.append(f"line {i}: schema must be aiwall.audit.v1")
        for field in REQUIRED_SAMPLE_FIELDS:
            if field not in event:
                errors.append(f"line {i}: missing field {field}")
        rid = str(event.get("request_id") or "")
        if not rid:
            errors.append(f"line {i}: empty request_id")
        elif rid in seen:
            errors.append(f"line {i}: duplicate request_id {rid}")
        else:
            seen.add(rid)
    return errors


def check_expected_hits(events: list[dict], expected: dict) -> list[str]:
    errors: list[str] = []
    by_id = {str(e.get("request_id") or ""): e for e in events}
    hits = expected.get("hits") or []
    if len(hits) != len(events):
        errors.append(
            f"expected_hits covers {len(hits)} request_ids but sample has {len(events)} events"
        )

    wazuh = _load_wazuh_alerts(WAZUH_RULES)
    sigma = _load_sigma_selections()
    loki_pack = json.loads(LOKI_PACK.read_text())
    loki_by_id = {q["id"]: q for q in loki_pack.get("queries") or []}

    covered_ids = {str(h.get("request_id") or "") for h in hits}
    for rid in by_id:
        if rid not in covered_ids:
            errors.append(f"sample request_id {rid} missing from expected_hits.json")

    for entry in hits:
        rid = str(entry.get("request_id") or "")
        event = by_id.get(rid)
        if event is None:
            errors.append(f"expected hit for unknown request_id {rid}")
            continue

        wazuh_id = entry.get("wazuh_rule_id")
        firing = [rule_id for rule_id, rule in wazuh.items() if _wazuh_matches(rule, event)]
        if wazuh_id is None:
            if firing:
                errors.append(f"{rid}: expected no Wazuh alert, got {firing}")
        else:
            if firing != [wazuh_id]:
                errors.append(f"{rid}: expected Wazuh [{wazuh_id}], got {firing}")

        sigma_name = entry.get("sigma_rule")
        if sigma_name is None:
            unexpected = [
                name for name, sel in sigma.items() if _sigma_matches(sel, event)
            ]
            if unexpected:
                errors.append(f"{rid}: expected no Sigma hit, got {unexpected}")
        else:
            if sigma_name not in sigma:
                errors.append(f"{rid}: missing Sigma rule file {sigma_name}.yml")
            elif not _sigma_matches(sigma[sigma_name], event):
                errors.append(f"{rid}: Sigma {sigma_name} does not match event")
            else:
                extras = [
                    name
                    for name, sel in sigma.items()
                    if name != sigma_name and _sigma_matches(sel, event)
                ]
                if extras:
                    errors.append(f"{rid}: unexpected extra Sigma hits {extras}")

        expect_loki = set(entry.get("loki_query_ids") or [])
        actual_loki = {
            qid
            for qid, query in loki_by_id.items()
            if _loki_matches(query.get("filters") or {}, event)
        }
        if actual_loki != expect_loki:
            errors.append(
                f"{rid}: Loki queries expected {sorted(expect_loki)}, got {sorted(actual_loki)}"
            )

    return errors


def run_pack_tests() -> list[str]:
    errors: list[str] = []
    for script in PACK_TESTS:
        if not script.is_file():
            errors.append(f"missing pack test: {script}")
            continue
        print(f"--- {script.relative_to(ROOT)}")
        proc = subprocess.run(
            [sys.executable, str(script)],
            cwd=str(ROOT),
            check=False,
        )
        if proc.returncode != 0:
            errors.append(f"{script.relative_to(ROOT)} exited {proc.returncode}")
    return errors


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--skip-pack-tests",
        action="store_true",
        help="Only run corpus + expected_hits matrix (no pack scripts)",
    )
    args = parser.parse_args(argv)

    for path in (EXPECTED_PATH, SAMPLE_JSONL, WAZUH_RULES, LOKI_PACK):
        if not path.is_file():
            print(f"missing {path}", file=sys.stderr)
            return 1
    if not SIGMA_DIR.is_dir():
        print(f"missing {SIGMA_DIR}", file=sys.stderr)
        return 1

    expected = json.loads(EXPECTED_PATH.read_text())
    if expected.get("schema") != "aiwall.validation.expected.v1":
        print("expected_hits.json: bad schema", file=sys.stderr)
        return 1

    events = _load_events(SAMPLE_JSONL)
    print(f"corpus: {len(events)} events from {SAMPLE_JSONL.relative_to(ROOT)}")

    errors = check_corpus(events)
    if errors:
        for err in errors:
            print(f"FAIL corpus: {err}", file=sys.stderr)
        return 1
    print("ok corpus schema/fields/request_ids")

    hit_errors = check_expected_hits(events, expected)
    if hit_errors:
        for err in hit_errors:
            print(f"FAIL hits: {err}", file=sys.stderr)
        return 1
    print(f"ok expected hits matrix ({len(expected.get('hits') or [])} request_ids)")

    if not args.skip_pack_tests:
        pack_errors = run_pack_tests()
        if pack_errors:
            for err in pack_errors:
                print(f"FAIL pack: {err}", file=sys.stderr)
            return 1
        print(f"ok {len(PACK_TESTS)} pack tests")

    print("PASS: validate_rules — sample corpus matches expected detection hits")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
