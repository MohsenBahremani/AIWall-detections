#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Mohsen Bah
# SPDX-License-Identifier: Apache-2.0
"""Offline check: Grafana dashboard targets the sample Loki datasource."""

from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
DASHBOARD = ROOT / "grafana" / "dashboards" / "aiwall-overview.json"
DATASOURCE = ROOT / "grafana" / "provisioning" / "datasources" / "loki.yml"
COMPOSE = ROOT / "grafana" / "docker-compose.yml"

REQUIRED_TITLES = {
    "Events",
    "Blocks",
    "Estimated cost",
    "Decisions",
    "Decisions over time",
    "Top models",
    "Top providers",
}


def main() -> int:
    for path in (DASHBOARD, DATASOURCE, COMPOSE):
        if not path.is_file():
            print(f"missing {path}", file=sys.stderr)
            return 1

    dashboard = json.loads(DASHBOARD.read_text())
    if dashboard.get("uid") != "aiwall-overview":
        print("dashboard uid must be aiwall-overview", file=sys.stderr)
        return 1
    if dashboard.get("title") != "AIWall Overview":
        print("unexpected dashboard title", file=sys.stderr)
        return 1

    panels = dashboard.get("panels") or []
    titles = {panel.get("title") for panel in panels}
    missing = REQUIRED_TITLES - titles
    if missing:
        print(f"missing panels: {sorted(missing)}", file=sys.stderr)
        return 1

    ds_hits = 0
    query_bits = {"decision", "model", "provider", "estimated_cost"}
    found_bits: set[str] = set()
    for panel in panels:
        ds = panel.get("datasource") or {}
        if ds.get("uid") == "aiwall-loki":
            ds_hits += 1
        for target in panel.get("targets") or []:
            expr = str(target.get("expr") or "")
            for bit in query_bits:
                if bit in expr:
                    found_bits.add(bit)
            if "aiwall.audit.v1" not in expr and panel.get("type") != "logs":
                # logs panel may only filter schema in expr too — require schema somewhere
                pass
            if "schema" in expr or "aiwall.audit.v1" in expr:
                found_bits.add("schema")

    if ds_hits < len(REQUIRED_TITLES):
        print(
            f"expected each required panel to use uid aiwall-loki "
            f"(matched {ds_hits} panels)",
            file=sys.stderr,
        )
        return 1
    if "schema" not in found_bits:
        print("queries should filter schema=aiwall.audit.v1", file=sys.stderr)
        return 1
    for bit in ("decision", "model", "provider", "estimated_cost"):
        if bit not in found_bits:
            print(f"missing query coverage for {bit}", file=sys.stderr)
            return 1

    ds_text = DATASOURCE.read_text()
    if "uid: aiwall-loki" not in ds_text or "type: loki" not in ds_text:
        print("datasource provisioning must define aiwall-loki", file=sys.stderr)
        return 1
    if "loki:" not in COMPOSE.read_text() or "grafana:" not in COMPOSE.read_text():
        print("docker-compose must include loki and grafana services", file=sys.stderr)
        return 1

    print(
        "PASS: AIWall Overview dashboard wired to sample Loki datasource "
        f"({len(panels)} panels)"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
