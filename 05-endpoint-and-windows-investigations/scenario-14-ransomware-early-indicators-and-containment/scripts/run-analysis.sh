#!/usr/bin/env bash
set -euo pipefail

SCENARIO_DIR="${1:-$(pwd)}"
RAW_DIR="$SCENARIO_DIR/evidence/raw"
WORKING_DIR="$SCENARIO_DIR/evidence/working"

for file in windows-sysmon.log windows-security.log windows-powershell.log; do
  test -s "$RAW_DIR/$file" || {
    echo "Missing raw evidence: $RAW_DIR/$file" >&2
    exit 1
  }
done

python3 "$SCENARIO_DIR/scripts/scenario14_first_pass.py" \
  --raw-dir "$RAW_DIR" \
  --working-dir "$WORKING_DIR"

python3 "$SCENARIO_DIR/scripts/scenario14_precise_verify.py" \
  --db "$WORKING_DIR/scenario14-events.sqlite" \
  --output-dir "$WORKING_DIR"

echo "Analysis complete."
echo "Review: $WORKING_DIR/compact-verification.txt"
