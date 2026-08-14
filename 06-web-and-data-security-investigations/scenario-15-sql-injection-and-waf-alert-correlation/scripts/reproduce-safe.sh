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
python3 "$SCENARIO_DIR/scripts/build_reproduction_sample.py" "$SCENARIO_DIR"

if git -C "$SCENARIO_DIR" rev-parse --is-inside-work-tree >/dev/null 2>&1; then
  python3 "$SCENARIO_DIR/scripts/portfolio_validator.py" "$SCENARIO_DIR" --git-aware
else
  python3 "$SCENARIO_DIR/scripts/portfolio_validator.py" "$SCENARIO_DIR" --local-reproduction
fi

echo "Safe offline analytical reproduction complete. Raw and working evidence remain local; curated processed evidence was not overwritten."
