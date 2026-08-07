# GitHub Publishing Guide

Before staging:

```bash
git -C "$REPO_ROOT" status --short -- "$SCENARIO_DIR"
bash "$SCENARIO_DIR/scripts/safe-reproduce.sh"
git -C "$REPO_ROOT" check-ignore -v "$SCENARIO_DIR/evidence/raw" "$SCENARIO_DIR/evidence/working"
```

Stage only Scenario 19:

```bash
git -C "$REPO_ROOT" add -- "08-detection-engineering-and-threat-hunting/scenario-19-detection-rule-development-and-false-positive-tuning"
git -C "$REPO_ROOT" diff --cached --check
git -C "$REPO_ROOT" --no-pager diff --cached --stat
```

Do not use `git add -A` while local evidence/working material is present. Review all staged files before commit. Recommended commit message:

```text
Complete Scenario 19 detection rule development and false-positive tuning
```
