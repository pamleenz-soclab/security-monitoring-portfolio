# GitHub Publishing Guide

## Copy the package

From a new terminal:

```bash
export REPO_ROOT="/Users/pamlee/Documents/GitHub/security-monitoring-portfolio"
export SCENARIO_DIR="$REPO_ROOT/07-cloud-identity-and-privilege-investigations/scenario-18-cloud-privilege-and-oauth-application-abuse"

mkdir -p "$SCENARIO_DIR"
rsync -av /path/to/scenario-18-cloud-privilege-and-oauth-application-abuse/ "$SCENARIO_DIR/"
```

## Validate publication boundaries

```bash
python3 "$SCENARIO_DIR/scripts/validation/portfolio_validator.py" \
  --scenario-dir "$SCENARIO_DIR" \
  --repo-root "$REPO_ROOT"
```

Expected result: `PASS` with no tracked raw or working evidence.

## Review status

```bash
GIT_PAGER=cat git -C "$REPO_ROOT" status --short -- "$SCENARIO_DIR"

git -C "$REPO_ROOT" check-ignore -v \
  "$SCENARIO_DIR/evidence/raw/.gitkeep" \
  "$SCENARIO_DIR/evidence/working/.gitkeep"
```

The `.gitkeep` files should be visible to Git. Generated files below raw and working should be ignored.

## Stage files

```bash
git -C "$REPO_ROOT" add -- "$SCENARIO_DIR"

git -C "$REPO_ROOT" diff --cached --check

GIT_PAGER=cat git -C "$REPO_ROOT" diff --cached --stat
```

## Confirm no local evidence is staged

```bash
git -C "$REPO_ROOT" diff --cached --name-only --   "$SCENARIO_DIR/evidence/raw"   "$SCENARIO_DIR/evidence/working"
```

Expected output contains only `.gitkeep`, or no output if those files were already tracked.

## Commit

```bash
git -C "$REPO_ROOT" commit   -m "Complete Scenario 18 cloud privilege and OAuth application abuse investigation"

git -C "$REPO_ROOT" push
```

## Final check

```bash
GIT_PAGER=cat git -C "$REPO_ROOT" status --short
```

The working tree should be clean.
