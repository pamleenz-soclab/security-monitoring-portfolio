#!/usr/bin/env bash
set -euo pipefail
SCENARIO_DIR="${1:-}"
MODE="${2:-}"
if [[ -z "$SCENARIO_DIR" ]]; then
  echo "Usage: $0 /path/to/scenario [--acquire]" >&2
  exit 2
fi
SCENARIO_DIR="$(cd "$SCENARIO_DIR" && pwd)"
if [[ "$MODE" == "--acquire" ]]; then
  bash "$SCENARIO_DIR/scripts/acquire-dataset.sh" "$SCENARIO_DIR"
fi
if [[ ! -f "$SCENARIO_DIR/evidence/raw/owasp.zip" ]]; then
  echo "Missing evidence/raw/owasp.zip. Re-run with --acquire or place the verified archive locally." >&2
  exit 1
fi
bash "$SCENARIO_DIR/scripts/run-first-pass.sh" "$SCENARIO_DIR"
bash "$SCENARIO_DIR/scripts/run-precise-validation.sh" "$SCENARIO_DIR"
python3 "$SCENARIO_DIR/scripts/build_processed_evidence.py" "$SCENARIO_DIR"
python3 "$SCENARIO_DIR/scripts/portfolio_validator.py" "$SCENARIO_DIR"
echo "Safe offline reproduction complete. Raw and working evidence remain Git ignored."
