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
ATLAS_MAP = ROOT / "docs" / "atlas-mapping.json"
COVERAGE_MD = ROOT / "docs" / "coverage-matrix.md"
PLAYBOOKS = (
    ROOT / "playbooks" / "secret-leak-detected.md",
    ROOT / "playbooks" / "child-safety-block.md",
    ROOT / "playbooks" / "suspicious-agent-action.md",
)

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


_ATLAS_ID_RE = re.compile(r"^AML\.T\d{4}(?:\.\d{3})?$")


def check_atlas_coverage() -> list[str]:
    """Every detection maps to ≥1 ATLAS technique; packs stay aligned."""
    errors: list[str] = []
    if not ATLAS_MAP.is_file():
        return [f"missing {ATLAS_MAP}"]
    if not COVERAGE_MD.is_file():
        return [f"missing {COVERAGE_MD}"]

    mapping = json.loads(ATLAS_MAP.read_text())
    if mapping.get("schema") != "aiwall.atlas.mapping.v1":
        errors.append("atlas-mapping.json: bad schema")
        return errors

    detections = mapping.get("detections") or []
    if len(detections) < 4:
        errors.append(f"atlas-mapping.json: expected >= 4 detections, got {len(detections)}")

    wazuh_ids = set(_load_wazuh_alerts(WAZUH_RULES))
    sigma_stems = {p.stem for p in SIGMA_DIR.glob("*.yml")}
    loki_pack = json.loads(LOKI_PACK.read_text())
    loki_by_id = {q["id"]: q for q in loki_pack.get("queries") or []}

    mapped_wazuh: set[int] = set()
    mapped_sigma: set[str] = set()
    mapped_loki: set[str] = set()

    for entry in detections:
        det_id = entry.get("id") or "<missing>"
        atlas = entry.get("atlas") or []
        if not atlas:
            errors.append(f"{det_id}: missing atlas techniques")
            continue
        primary = [a for a in atlas if a.get("primary")]
        if not primary:
            errors.append(f"{det_id}: need at least one primary ATLAS technique")
        for tech in atlas:
            tid = str(tech.get("id") or "")
            if not _ATLAS_ID_RE.match(tid):
                errors.append(f"{det_id}: invalid ATLAS id {tid!r}")
            if not (tech.get("name") or "").strip():
                errors.append(f"{det_id}: ATLAS {tid} missing name")

        wazuh_id = entry.get("wazuh_rule_id")
        if wazuh_id is not None:
            mapped_wazuh.add(int(wazuh_id))
            if int(wazuh_id) not in wazuh_ids:
                errors.append(f"{det_id}: wazuh_rule_id {wazuh_id} not in rules XML")

        sigma_name = entry.get("sigma_rule")
        if sigma_name:
            mapped_sigma.add(str(sigma_name))
            if sigma_name not in sigma_stems:
                errors.append(f"{det_id}: missing Sigma rule {sigma_name}.yml")

        for qid in entry.get("loki_query_ids") or []:
            mapped_loki.add(str(qid))
            query = loki_by_id.get(qid)
            if query is None:
                errors.append(f"{det_id}: missing Loki query {qid}")
                continue
            expect_ids = {
                str(a["id"]) for a in atlas if a.get("id")
            }
            declared = {str(x) for x in (query.get("atlas_ids") or [])}
            if declared != expect_ids:
                errors.append(
                    f"{det_id}: Loki {qid} atlas_ids {sorted(declared)} "
                    f"!= mapping {sorted(expect_ids)}"
                )

        md = COVERAGE_MD.read_text()
        if det_id.replace("aiwall_", "").replace("_", " ") not in md.lower():
            # Title or primary id must appear in the human matrix
            title = str(entry.get("title") or "")
            primary_id = next(
                (str(a["id"]) for a in atlas if a.get("primary")),
                "",
            )
            if title not in md and primary_id not in md:
                errors.append(
                    f"{det_id}: coverage-matrix.md should mention title or {primary_id}"
                )

    missing_wazuh = wazuh_ids - mapped_wazuh
    if missing_wazuh:
        errors.append(f"Wazuh alert rules missing from ATLAS map: {sorted(missing_wazuh)}")
    missing_sigma = sigma_stems - mapped_sigma
    if missing_sigma:
        errors.append(f"Sigma rules missing from ATLAS map: {sorted(missing_sigma)}")

    # Every Loki query except roll-ups must be mapped
    for qid, query in loki_by_id.items():
        if qid == "aiwall_all_blocks":
            continue
        if qid not in mapped_loki:
            errors.append(f"Loki query {qid} missing from ATLAS map")
        elif not (query.get("atlas_ids") or []):
            errors.append(f"Loki query {qid} missing atlas_ids")

    return errors


def check_playbooks() -> list[str]:
    errors: list[str] = []
    required_headings = ("## Triage", "## Response")
    for path in PLAYBOOKS:
        if not path.is_file():
            errors.append(f"missing playbook {path.relative_to(ROOT)}")
            continue
        text = path.read_text()
        for heading in required_headings:
            if heading not in text:
                errors.append(f"{path.name}: missing {heading} section")
        if len(text.strip()) < 400:
            errors.append(f"{path.name}: playbook looks too short")
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

    for path in (EXPECTED_PATH, SAMPLE_JSONL, WAZUH_RULES, LOKI_PACK, ATLAS_MAP, COVERAGE_MD):
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

    atlas_errors = check_atlas_coverage()
    if atlas_errors:
        for err in atlas_errors:
            print(f"FAIL atlas: {err}", file=sys.stderr)
        return 1
    print("ok ATLAS coverage (every detection mapped)")

    playbook_errors = check_playbooks()
    if playbook_errors:
        for err in playbook_errors:
            print(f"FAIL playbook: {err}", file=sys.stderr)
        return 1
    print(f"ok {len(PLAYBOOKS)} response playbooks")

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
