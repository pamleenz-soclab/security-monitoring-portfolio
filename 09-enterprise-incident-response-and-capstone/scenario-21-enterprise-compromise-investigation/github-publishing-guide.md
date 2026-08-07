# GitHub Publishing Guide

Publish:

- Markdown reports,
- final validator,
- small processed CSV/TSV evidence,
- source/hash/boundary records.

Do not publish:

- raw ZIP/PCAP files,
- the extracted ~385 MB host JSON,
- working/precision-validation raw event subsets,
- unredacted long encoded payloads.

## Pre-commit sequence

```bash
cd "/Users/pamlee/Documents/GitHub/security-monitoring-portfolio"

SCENARIO_DIR="09-enterprise-incident-response-and-capstone/scenario-21-enterprise-compromise-investigation"

python3 "$SCENARIO_DIR/scripts/scenario21-final-validator.py" \
  --repo-root "/Users/pamlee/Documents/GitHub/security-monitoring-portfolio"

git status --short --untracked-files=all

git check-ignore -v \
  "$SCENARIO_DIR/evidence/raw/host/apt29_evals_day1_manual.zip" \
  "$SCENARIO_DIR/evidence/working/host/apt29_evals_day1_manual_2020-05-01225525.json"

git diff --check

git add "$SCENARIO_DIR"

git diff --cached --check
git diff --cached --name-only -- "$SCENARIO_DIR"
```

Before committing, confirm that no actual path under `evidence/raw/` or `evidence/working/` is staged.

Suggested commit message:

```text
Complete Scenario 21 enterprise compromise investigation
```
