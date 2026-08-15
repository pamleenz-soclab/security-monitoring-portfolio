#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'USAGE'
Usage:
  safe-reproducibility-wrapper.sh [--repo-root /path/to/security-monitoring-portfolio] [--force-regenerate]

The script only generates deterministic synthetic evidence locally. It never connects to a real tenant.
USAGE
}

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SCENARIO_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
REPO_ROOT=""
FORCE=0

while [[ $# -gt 0 ]]; do
  case "$1" in
    --repo-root) REPO_ROOT="${2:-}"; shift 2 ;;
    --force-regenerate) FORCE=1; shift ;;
    -h|--help) usage; exit 0 ;;
    *) echo "Unknown argument: $1" >&2; usage; exit 2 ;;
  esac
done

if [[ -z "$REPO_ROOT" ]]; then
  REPO_ROOT="$(git -C "$SCENARIO_DIR" rev-parse --show-toplevel 2>/dev/null || true)"
fi
if [[ -n "$REPO_ROOT" ]]; then
  REPO_ROOT="$(cd "$REPO_ROOT" && pwd)"
fi

RAW_PARENT="$SCENARIO_DIR/evidence/raw"
RAW_DIR="$RAW_PARENT/synthetic-event-package"
WORKING_DIR="$SCENARIO_DIR/evidence/working"
mkdir -p "$RAW_PARENT" "$WORKING_DIR" "$SCENARIO_DIR/evidence/processed"

if [[ -n "$REPO_ROOT" && -d "$REPO_ROOT/.git" ]]; then
  echo "[1/8] Verify local evidence directories are ignored"
  for d in "$RAW_PARENT" "$WORKING_DIR"; do
    probe="$d/.scenario18-ignore-probe"
    : > "$probe"
    if ! git -C "$REPO_ROOT" check-ignore -q "$probe"; then
      rm -f "$probe"
      echo "ERROR: local evidence path is not ignored: $d" >&2
      exit 2
    fi
    rm -f "$probe"
  done
else
  echo "[1/8] Git ignore check skipped: repository root unavailable"
fi

GEN_ARGS=(--output "$RAW_DIR")
if [[ "$FORCE" -eq 1 ]]; then GEN_ARGS+=(--force); fi

echo "[2/8] Generate deterministic synthetic source evidence when needed"
if [[ ! -f "$RAW_DIR/00-package-metadata.json" || "$FORCE" -eq 1 ]]; then
  python3 "$SCRIPT_DIR/generation/generate_synthetic_event.py" "${GEN_ARGS[@]}"
else
  echo "Raw package already exists; generation skipped."
fi

echo "[3/8] Validate synthetic package"
python3 "$SCRIPT_DIR/validation/validate_synthetic_package.py" \
  --input "$RAW_DIR" \
  --report "$WORKING_DIR/synthetic-package-validation.json"

echo "[4/8] Run first-pass parser"
python3 "$SCRIPT_DIR/parsing/first_pass_parser.py" \
  --input "$RAW_DIR" \
  --output "$WORKING_DIR"

echo "[5/8] Run stable-ID correlation"
python3 "$SCRIPT_DIR/correlation/precise_cloud_privilege_correlation.py" \
  --input "$RAW_DIR" \
  --output "$WORKING_DIR"

echo "[6/8] Assess permission risk"
python3 "$SCRIPT_DIR/correlation/permission_risk.py" \
  --input "$RAW_DIR" \
  --output "$WORKING_DIR"

echo "[7/8] Run publishable-content sanitisation"
python3 "$SCRIPT_DIR/validation/sanitisation_test.py" \
  --scenario-dir "$SCENARIO_DIR" \
  --allow-synthetic-uuids \
  --report "$WORKING_DIR/publishable-sanitisation.json"

echo "[8/8] Validate portfolio and Git boundary"
VALIDATOR_ARGS=(--scenario-dir "$SCENARIO_DIR")
if [[ -n "$REPO_ROOT" && -d "$REPO_ROOT/.git" ]]; then
  VALIDATOR_ARGS+=(--repo-root "$REPO_ROOT")
fi
python3 "$SCRIPT_DIR/validation/portfolio_validator.py" "${VALIDATOR_ARGS[@]}"

echo
echo "=== COMPACT RESULT ==="
cat "$WORKING_DIR/compact-first-pass-summary.txt"
echo "Validation: $WORKING_DIR/synthetic-package-validation.json"
echo "Correlation: $WORKING_DIR/precise-cloud-privilege-correlation-summary.json"
echo "Permission risk: $WORKING_DIR/permission-risk-summary.json"
echo "Sanitisation: $WORKING_DIR/publishable-sanitisation.json"
