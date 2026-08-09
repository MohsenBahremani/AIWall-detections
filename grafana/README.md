# Grafana dashboard for AIWall

## Overview (Phase 6.5)

Dashboard: [`dashboards/aiwall-overview.json`](dashboards/aiwall-overview.json)

Panels (Loki datasource `aiwall-loki`, sample corpus):

| Panel | Shows |
|---|---|
| Events / Blocks / Estimated cost | Totals for the selected range |
| Decisions | Pie of `decision` values |
| Decisions over time | Stacked bars |
| Top models / Top providers | `topk` by event count |
| Recent AIWall events | Raw `aiwall.audit.v1` lines |

Default time range is `now-1h` → `now`. Promtail stamps lines at ingest time (the JSON `timestamp` field is unchanged for LogQL `| json`).

## Run the sample stack

From this directory:

```bash
docker compose up -d
```

Open http://localhost:3000/d/aiwall-overview (anonymous viewer).

Data path:

```text
validation/samples/aiwall.audit.v1.sample.jsonl
        │
        v
   Promtail  -->  Loki  -->  Grafana (AIWall Overview)
```

Stop:

```bash
docker compose down
```

## Offline check

```bash
python3 grafana/tests/test_dashboard.py
```

## Files

| Path | Role |
|---|---|
| `dashboards/aiwall-overview.json` | Dashboard model |
| `provisioning/datasources/loki.yml` | Datasource `aiwall-loki` |
| `provisioning/dashboards/dashboards.yml` | Auto-load dashboards |
| `loki-config.yml` / `promtail-config.yml` | Sample ingest |
| `docker-compose.yml` | Local Grafana + Loki + Promtail |
