#!/usr/bin/env bash
set -euo pipefail
if [[ $# -ne 1 ]]; then
  echo "Usage: $0 SCENARIO_DIR" >&2
  exit 2
fi
SCENARIO_DIR="$1"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
python3 "$SCRIPT_DIR/precise_validate.py" "$SCENARIO_DIR"
