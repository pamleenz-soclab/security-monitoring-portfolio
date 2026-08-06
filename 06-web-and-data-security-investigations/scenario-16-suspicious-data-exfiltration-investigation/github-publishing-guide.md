# GitHub Publishing Guide

## 1. Copy the final package into the repository

Merge the contents of this directory into:

```text
06-web-and-data-security-investigations/
scenario-16-suspicious-data-exfiltration-investigation/
```

Do not copy the local raw or working evidence.

## 2. Validate publication safety

```bash
export REPO_ROOT="/Users/pamlee/Documents/GitHub/security-monitoring-portfolio"
export SCENARIO_DIR="$REPO_ROOT/06-web-and-data-security-investigations/scenario-16-suspicious-data-exfiltration-investigation"

python3 "$SCENARIO_DIR/scripts/validation/portfolio_validator.py"   --scenario "$SCENARIO_DIR"   --mode git-aware   --repo-root "$REPO_ROOT"

python3 "$SCENARIO_DIR/scripts/sanitisation/sanitisation_tests.py"   --scenario "$SCENARIO_DIR"
```

The Git-aware validator permits local files under raw/working only when Git ignores them and they are not tracked.

## 3. Review Git visibility

```bash
git -C "$REPO_ROOT" check-ignore -v --no-index   "$SCENARIO_DIR/evidence/raw/test.pcap"   "$SCENARIO_DIR/evidence/working/test.sqlite"

git -C "$REPO_ROOT" --no-pager status --short -- "$SCENARIO_DIR"

git -C "$REPO_ROOT" ls-files   "$SCENARIO_DIR/evidence/raw"   "$SCENARIO_DIR/evidence/working"
```

Only `.gitkeep` should be tracked under raw/working.

## 4. Stage and inspect

```bash
git -C "$REPO_ROOT" add --   "06-web-and-data-security-investigations/scenario-16-suspicious-data-exfiltration-investigation"

git -C "$REPO_ROOT" diff --cached --check

git -C "$REPO_ROOT" --no-pager diff --cached --stat

git -C "$REPO_ROOT" --no-pager diff --cached --name-only
```

Do not continue if trailing whitespace, conflict markers, raw evidence, PCAP, databases, archives, or sensitive content appear.

## 5. Commit and push

```bash
git -C "$REPO_ROOT" commit -m   "Complete Scenario 16 suspicious data exfiltration investigation"

git -C "$REPO_ROOT" push
```

The commands use `git -C` and `--no-pager` to avoid path ambiguity and terminal pagination.
