#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Mohsen Bah
# SPDX-License-Identifier: Apache-2.0
# Lab loop: optional red-team regression → export audit JSONL → score SIEM hits.
#
# Usage:
#   ./scripts/validate_export.sh
#   AIWALL_BASE_URL=http://127.0.0.1:8080 ./scripts/validate_export.sh --with-regression
#   ./scripts/validate_export.sh --file /tmp/aiwall.audit.jsonl --require-reasons secret-detected
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BASE_URL="${AIWALL_BASE_URL:-http://127.0.0.1:8080}"
WINDOW_HOURS="${AIWALL_EXPORT_WINDOW_HOURS:-24}"
OUT="${AIWALL_EXPORT_FILE:-/tmp/aiwall.audit.export.jsonl}"
WITH_REGRESSION=0
REQUIRE_REASONS=()
FILE_OVERRIDE=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --with-regression) WITH_REGRESSION=1; shift ;;
    --file) FILE_OVERRIDE="${2:-}"; shift 2 ;;
    --require-reasons)
      shift
      while [[ $# -gt 0 && "$1" != --* ]]; do
        REQUIRE_REASONS+=("$1")
        shift
      done
      ;;
    -h|--help)
      sed -n '2,12p' "$0"
      exit 0
      ;;
    *)
      echo "unknown arg: $1" >&2
      exit 2
      ;;
  esac
done

if [[ "${WITH_REGRESSION}" -eq 1 ]]; then
  REDTEAM_ROOT="$(cd "${ROOT}/../AIWall-redteam" 2>/dev/null && pwd || true)"
  if [[ -z "${REDTEAM_ROOT}" || ! -f "${REDTEAM_ROOT}/scripts/run_regression.py" ]]; then
    echo "AIWall-redteam not found next to AIWall-detections; skip --with-regression" >&2
    exit 1
  fi
  echo "==> redteam regression against ${BASE_URL}"
  (
    cd "${REDTEAM_ROOT}"
    # Prefer venv if present
    if [[ -x .venv/bin/python ]]; then
      .venv/bin/python scripts/run_regression.py
    else
      python3 scripts/run_regression.py
    fi
  )
fi

if [[ -n "${FILE_OVERRIDE}" ]]; then
  OUT="${FILE_OVERRIDE}"
  echo "==> using existing export ${OUT}"
else
  echo "==> exporting ${BASE_URL}/events/export.jsonl?window_hours=${WINDOW_HOURS}"
  curl -fsS "${BASE_URL}/events/export.jsonl?window_hours=${WINDOW_HOURS}" -o "${OUT}"
fi

echo "==> scoring export against Wazuh rules"
ARGS=(python3 "${ROOT}/scripts/check_export_hits.py" "${OUT}")
if [[ ${#REQUIRE_REASONS[@]} -gt 0 ]]; then
  ARGS+=(--require-reasons "${REQUIRE_REASONS[@]}")
fi
"${ARGS[@]}"

echo "==> offline pack validation (sample corpus)"
python3 "${ROOT}/validation/validate_rules.py" --skip-pack-tests

echo "PASS: export scored; sample pack still green"
