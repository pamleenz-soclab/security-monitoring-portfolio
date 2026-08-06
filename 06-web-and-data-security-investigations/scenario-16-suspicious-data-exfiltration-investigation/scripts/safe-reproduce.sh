#!/usr/bin/env bash
set -euo pipefail

SCENARIO_DIR="${1:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}"
MODE="${MODE:-standalone}"
REPO_ROOT="${REPO_ROOT:-}"

command -v python3 >/dev/null || { echo "python3 is required" >&2; exit 1; }

VALIDATOR="$SCENARIO_DIR/scripts/validation/portfolio_validator.py"
SANITISER="$SCENARIO_DIR/scripts/sanitisation/sanitisation_tests.py"
TRANSFER="$SCENARIO_DIR/evidence/processed/transfer-outcome-assessment.csv"
VOLUME="$SCENARIO_DIR/evidence/processed/network-flow-and-volume-analysis.csv"
TMP="${TMPDIR:-/tmp}/scenario16-reproduce-$$"
trap 'rm -rf "$TMP"' EXIT
mkdir -p "$TMP"

if [[ "$MODE" == "git-aware" ]]; then
  [[ -n "$REPO_ROOT" ]] || { echo "REPO_ROOT is required for git-aware mode" >&2; exit 1; }
  python3 "$VALIDATOR" --scenario "$SCENARIO_DIR" --mode git-aware --repo-root "$REPO_ROOT"
else
  python3 "$VALIDATOR" --scenario "$SCENARIO_DIR" --mode standalone
fi

python3 "$SANITISER" --scenario "$SCENARIO_DIR"
python3 "$SCENARIO_DIR/scripts/correlation/precise_correlation.py" \
  --input "$TRANSFER" --output "$TMP/recomputed-transfer-outcomes.csv"
python3 "$SCENARIO_DIR/scripts/volume-analysis/baseline_volume_analysis.py" \
  --input "$VOLUME" --output "$TMP/recomputed-volume-summary.csv"

echo "Safe reproducibility checks completed."
echo "Temporary outputs: $TMP (removed on exit)"
