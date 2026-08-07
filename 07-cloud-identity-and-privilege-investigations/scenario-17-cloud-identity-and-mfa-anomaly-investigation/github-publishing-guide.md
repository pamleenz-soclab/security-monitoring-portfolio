# GitHub Publishing Guide

## 1. Extract the final package

The ZIP contains the Scenario 17 directory contents. Copy them into:

```text
07-cloud-identity-and-privilege-investigations/
└── scenario-17-cloud-identity-and-mfa-anomaly-investigation/
```

Do not overwrite local `evidence/raw/` or `evidence/working/` with public files.

## 2. Set variables in a new terminal

```bash
REPO_ROOT="/Users/pamlee/Documents/GitHub/security-monitoring-portfolio"

SCENARIO_DIR="$REPO_ROOT/07-cloud-identity-and-privilege-investigations/scenario-17-cloud-identity-and-mfa-anomaly-investigation"
```

## 3. Run sanitisation tests

```bash
python3   "$SCENARIO_DIR/scripts/sanitisation/sanitisation_tests.py"   --scenario-dir "$SCENARIO_DIR"
```

Purpose: scans publishable files for credentials, tokens, real email domains, raw UUID identifiers, unsafe archives, and prohibited headers.

## 4. Run Git-aware validation

```bash
python3   "$SCENARIO_DIR/scripts/validation/portfolio_validator.py"   --scenario-dir "$SCENARIO_DIR"   --repo-root "$REPO_ROOT"   --mode git-aware
```

Purpose: permits local raw and working files only when they are ignored and untracked.

## 5. Inspect Git status

```bash
GIT_PAGER=cat git -C "$REPO_ROOT" status --short -- "$SCENARIO_DIR"
```

Expected: documents, processed evidence, detections, queries, and scripts are visible. Raw and working content should not appear.

## 6. Stage Scenario 17

```bash
git -C "$REPO_ROOT" add -- "$SCENARIO_DIR"
```

## 7. Validate the staged diff

```bash
git -C "$REPO_ROOT" diff --cached --check
```

Expected: no trailing whitespace or conflict-marker errors.

## 8. Confirm no raw or working files are staged

```bash
git -C "$REPO_ROOT" diff --cached --name-only -- "$SCENARIO_DIR" |
  grep -E '/evidence/(raw|working)/' |
  grep -vE '/\.gitkeep$' || true
```

Expected: no output.

## 9. Review staged files without a pager

```bash
GIT_PAGER=cat git -C "$REPO_ROOT" --no-pager diff   --cached --stat -- "$SCENARIO_DIR"
```

## 10. Commit and push

```bash
git -C "$REPO_ROOT" commit   -m "Complete Scenario 17 cloud identity and MFA anomaly investigation"

git -C "$REPO_ROOT" push
```
