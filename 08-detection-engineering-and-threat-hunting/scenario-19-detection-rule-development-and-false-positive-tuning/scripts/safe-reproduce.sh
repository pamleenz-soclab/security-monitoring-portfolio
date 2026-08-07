#!/bin/bash
set -euo pipefail

export PYTHONDONTWRITEBYTECODE=1

ROOT="$(cd "$(dirname "$0")/.." && pwd)"

find "$ROOT" \
  \( \
    -path "$ROOT/.venv" \
    -o -path "$ROOT/venv" \
    -o -path "$ROOT/evidence/raw" \
    -o -path "$ROOT/evidence/working" \
  \) -prune \
  -o -type d -name __pycache__ -exec rm -rf {} + \
  2>/dev/null || true

python3 "$ROOT/scripts/fixture-building/build_fixtures.py"
python3 "$ROOT/scripts/evaluation/test_runner.py" --root "$ROOT"
python3 "$ROOT/scripts/metrics/calculate_metrics.py"
python3 "$ROOT/scripts/sanitisation/sanitisation_tests.py"
python3 "$ROOT/scripts/validation/semantic_comparison_validator.py"
python3 "$ROOT/scripts/validation/portfolio_validator.py"
python3 "$ROOT/scripts/validation/git_aware_validator.py"
