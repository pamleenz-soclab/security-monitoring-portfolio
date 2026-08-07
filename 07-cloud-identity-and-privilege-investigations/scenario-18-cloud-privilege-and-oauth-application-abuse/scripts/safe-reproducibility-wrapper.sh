#!/bin/bash
set -euo pipefail

usage() {
  cat <<'EOF'
Usage:
  safe-reproducibility-wrapper.sh --repo-root /path/to/security-monitoring-portfolio [--force-regenerate]

The script:
1. Generates deterministic synthetic raw evidence if it does not exist.
2. Validates safety, schema shape, referential integrity, and SHA-256 records.
3. Creates first-pass working outputs and SQLite.
4. Performs stable-ID correlation.
5. Assesses permission risk.
6. Runs the Git-aware validator when the repository exists.
EOF
}

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
  echo "--repo-root is required" >&2
  exit 2
fi

REPO_ROOT="$(cd "$REPO_ROOT" && pwd)"
SCENARIO_DIR="$REPO_ROOT/07-cloud-identity-and-privilege-investigations/scenario-18-cloud-privilege-and-oauth-application-abuse"
RAW_DIR="$SCENARIO_DIR/evidence/raw/synthetic-event-package"
WORKING_DIR="$SCENARIO_DIR/evidence/working"
SCRIPT_DIR="$SCENARIO_DIR/scripts"

mkdir -p "$SCENARIO_DIR/evidence/raw" "$WORKING_DIR" "$SCENARIO_DIR/evidence/processed"
touch "$SCENARIO_DIR/evidence/raw/.gitkeep" "$WORKING_DIR/.gitkeep" "$SCENARIO_DIR/evidence/processed/.gitkeep"

GEN_ARGS=(--output "$RAW_DIR")
if [[ "$FORCE" -eq 1 ]]; then
  GEN_ARGS+=(--force)
fi

if [[ ! -f "$RAW_DIR/00-package-metadata.json" || "$FORCE" -eq 1 ]]; then
  python3 "$SCRIPT_DIR/generation/generate_synthetic_event.py" "${GEN_ARGS[@]}"
else
  echo "Raw package already exists; generation skipped."
fi

python3 "$SCRIPT_DIR/validation/validate_synthetic_package.py" \
  --input "$RAW_DIR" \
  --report "$WORKING_DIR/synthetic-package-validation.json"

python3 "$SCRIPT_DIR/parsing/first_pass_parser.py" \
  --input "$RAW_DIR" \
  --output "$WORKING_DIR"

python3 "$SCRIPT_DIR/correlation/precise_cloud_privilege_correlation.py" \
  --input "$RAW_DIR" \
  --output "$WORKING_DIR"

python3 "$SCRIPT_DIR/correlation/permission_risk.py" \
  --input "$RAW_DIR" \
  --output "$WORKING_DIR"

if [[ -d "$REPO_ROOT/.git" ]]; then
  python3 "$SCRIPT_DIR/validation/git_aware_validator.py" \
    --repo-root "$REPO_ROOT" \
    --scenario-dir "$SCENARIO_DIR" \
    --report "$WORKING_DIR/git-aware-validation.json"
else
  echo "Git-aware validation skipped: $REPO_ROOT is not a Git repository."
fi

echo
echo "=== COMPACT RESULT ==="
cat "$WORKING_DIR/compact-first-pass-summary.txt"
echo "Validation: $WORKING_DIR/synthetic-package-validation.json"
echo "Correlation: $WORKING_DIR/precise-cloud-privilege-correlation-summary.json"
echo "Permission risk: $WORKING_DIR/permission-risk-summary.json"
