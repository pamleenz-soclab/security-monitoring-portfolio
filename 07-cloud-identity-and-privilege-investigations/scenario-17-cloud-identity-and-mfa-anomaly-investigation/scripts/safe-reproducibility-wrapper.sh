#!/bin/bash
set -euo pipefail

REPO_ROOT="${REPO_ROOT:-/Users/pamlee/Documents/GitHub/security-monitoring-portfolio}"
SCENARIO_DIR="${SCENARIO_DIR:-$REPO_ROOT/07-cloud-identity-and-privilege-investigations/scenario-17-cloud-identity-and-mfa-anomaly-investigation}"

RAW_DIR="$SCENARIO_DIR/evidence/raw"
WORKING_DIR="$SCENARIO_DIR/evidence/working"

mkdir -p "$RAW_DIR" "$WORKING_DIR" "$SCENARIO_DIR/evidence/processed"

echo "[1/8] Verify raw and working paths are ignored"
for path in "$RAW_DIR" "$WORKING_DIR"; do
  probe="$path/.scenario17-ignore-probe"
  : > "$probe"
  if ! git -C "$REPO_ROOT" check-ignore -q "$probe"; then
    rm -f "$probe"
    echo "ERROR: $path is not ignored by Git" >&2
    exit 2
  fi
  rm -f "$probe"
done

echo "[2/8] Generate deterministic synthetic evidence"
python3 \
  "$SCENARIO_DIR/scripts/acquisition/scenario17_generate_synthetic_dataset.py" \
  --raw-dir "$RAW_DIR" \
  --force

echo "[3/8] Run first-pass parser"
FIRST_CONSOLE="$(mktemp)"
python3 \
  "$SCENARIO_DIR/scripts/parsing/scenario17_first_pass.py" \
  --raw-dir "$RAW_DIR" \
  --working-dir "$WORKING_DIR" \
  >"$FIRST_CONSOLE" 2>&1
mv "$FIRST_CONSOLE" "$WORKING_DIR/scenario17-first-pass-console.txt"

echo "[4/8] Build independent user baseline"
python3 \
  "$SCENARIO_DIR/scripts/analysis/user_baseline.py" \
  --raw-dir "$RAW_DIR" \
  --output "$WORKING_DIR/user-baseline-independent.csv"

echo "[5/8] Run precise identifier correlation"
PRECISE_CONSOLE="$(mktemp)"
python3 \
  "$SCENARIO_DIR/scripts/analysis/scenario17_precise_verification.py" \
  --scenario-dir "$SCENARIO_DIR" \
  >"$PRECISE_CONSOLE" 2>&1
mv "$PRECISE_CONSOLE" "$WORKING_DIR/scenario17-precise-verification-console.txt"

echo "[6/8] Build sanitised processed evidence"
python3 \
  "$SCENARIO_DIR/scripts/analysis/build_processed_evidence.py" \
  --scenario-dir "$SCENARIO_DIR"

echo "[7/8] Generate final publishable manifest"
python3 \
  "$SCENARIO_DIR/scripts/validation/generate_package_manifest.py" \
  --scenario-dir "$SCENARIO_DIR"

echo "[8/8] Run safety and Git-aware validation"
python3 \
  "$SCENARIO_DIR/scripts/sanitisation/sanitisation_tests.py" \
  --scenario-dir "$SCENARIO_DIR"

python3 \
  "$SCENARIO_DIR/scripts/validation/portfolio_validator.py" \
  --scenario-dir "$SCENARIO_DIR" \
  --repo-root "$REPO_ROOT" \
  --mode git-aware

echo "Scenario 17 reproduction and validation completed."
