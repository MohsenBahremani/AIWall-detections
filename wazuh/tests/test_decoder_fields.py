#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Mohsen Bah
# SPDX-License-Identifier: Apache-2.0
"""Offline check: AIWall decoder prematch + sample fields (no Wazuh required)."""

from __future__ import annotations

import json
import re
import sys
import xml.etree.ElementTree as ET
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
DECODER_XML = ROOT / "wazuh" / "decoders" / "aiwall_decoders.xml"
SAMPLE_JSONL = ROOT / "validation" / "samples" / "aiwall.audit.v1.sample.jsonl"

REQUIRED_FIELDS = (
    "schema",
    "id",
    "timestamp",
    "request_id",
    "provider",
    "model",
    "decision",
    "reason",
    "policy_id",
    "matched_rule_ids",
    "categories",
    "input_length",
    "output_length",
    "prompt_tokens",
    "completion_tokens",
    "total_tokens",
    "estimated_cost",
    "redaction_count",
    "latency_ms",
    "user_id",
)

PREMATCH_RE = re.compile(r'"schema"\s*:\s*"aiwall\.audit\.v1"')


def _load_prematches(path: Path) -> list[str]:
    raw = path.read_text()
    # Wazuh decoder files are multi-root; wrap for ElementTree.
    tree = ET.fromstring(f"<decoders>{raw}</decoders>")
    found: list[str] = []
    for decoder in tree.findall("decoder"):
        name = decoder.get("name") or ""
        prematch = decoder.findtext("prematch")
        plugin = decoder.findtext("plugin_decoder")
        if prematch and plugin and "JSON_Decoder" in plugin:
            found.append(prematch)
            if "aiwall.audit.v1" not in prematch:
                raise AssertionError(
                    f"decoder {name!r} prematch must target aiwall.audit.v1, got {prematch!r}"
                )
    if not found:
        raise AssertionError("no JSON_Decoder + prematch pair found in decoder XML")
    return found


def main() -> int:
    if not DECODER_XML.is_file():
        print(f"missing decoder: {DECODER_XML}", file=sys.stderr)
        return 1
    if not SAMPLE_JSONL.is_file():
        print(f"missing samples: {SAMPLE_JSONL}", file=sys.stderr)
        return 1

    _load_prematches(DECODER_XML)

    lines = [line for line in SAMPLE_JSONL.read_text().splitlines() if line.strip()]
    if not lines:
        print("sample file is empty", file=sys.stderr)
        return 1

    for index, line in enumerate(lines, start=1):
        if not PREMATCH_RE.search(line):
            print(f"line {index}: prematch would miss event", file=sys.stderr)
            return 1
        event = json.loads(line)
        missing = [name for name in REQUIRED_FIELDS if name not in event]
        if missing:
            print(f"line {index}: missing fields {missing}", file=sys.stderr)
            return 1
        if event.get("schema") != "aiwall.audit.v1":
            print(f"line {index}: bad schema {event.get('schema')!r}", file=sys.stderr)
            return 1
        # Named fields the JSON_Decoder would expose to rules:
        named = {
            "decision": event["decision"],
            "reason": event["reason"],
            "policy_id": event["policy_id"],
            "provider": event["provider"],
            "model": event["model"],
            "request_id": event["request_id"],
        }
        if not named["decision"]:
            print(f"line {index}: empty decision", file=sys.stderr)
            return 1
        print(f"line {index}: ok decoder fields -> {named}")

    print(f"PASS: {len(lines)} sample events match aiwall-audit decoder fields")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
