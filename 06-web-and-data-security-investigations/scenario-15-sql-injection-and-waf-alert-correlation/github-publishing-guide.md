# GitHub Publishing Guide

Set variables in every new terminal:

```bash
REPO_ROOT="/Users/pamlee/Documents/GitHub/security-monitoring-portfolio"
SCENARIO_REL="06-web-and-data-security-investigations/scenario-15-sql-injection-and-waf-alert-correlation"
SCENARIO_DIR="$REPO_ROOT/$SCENARIO_REL"
```

**Purpose:** Pins all subsequent commands to the intended repository and scenario.  
**Important parameters:** `git -C "$REPO_ROOT"` prevents accidental Git operations in a temporary source directory.

## 1. Copy the package contents

Extract the supplied ZIP and copy the scenario folder into:

```text
$REPO_ROOT/06-web-and-data-security-investigations/
```

Do not replace local `evidence/raw/` or `evidence/working/` data with published files.

## 2. Run the portfolio validator

```bash
python3 "$SCENARIO_DIR/scripts/portfolio_validator.py" "$SCENARIO_DIR" --git-aware
```

**Purpose:** Verifies required files, sanitisation boundaries and Git-ignore behaviour.  
**Expected output:** `PASS` with zero validation errors.  
**Abnormal output:** Missing required files, secret-like values, or raw/working files visible to Git.  
**Evidence impact:** Read-only.

## 3. Review Git status

```bash
git -C "$REPO_ROOT" status --short --ignored -- "$SCENARIO_REL"
```

**Purpose:** Confirms publishable files are visible while raw and working evidence appear with `!!`.  
**Abnormal output:** `owasp.zip`, extracted logs or SQLite files shown as `??` or staged.  
**Evidence impact:** Read-only.

## 4. Stage only Scenario 15

```bash
git -C "$REPO_ROOT" add -- "$SCENARIO_REL"
```

**Purpose:** Stages the scenario without changing the current working directory.  
**Important parameter:** `--` ends option parsing and protects path handling.  
**Evidence impact:** Updates the Git index only; original evidence remains unchanged.

## 5. Validate the staged set

```bash
git -C "$REPO_ROOT" diff --cached --check

git -C "$REPO_ROOT" diff --cached --name-only -- "$SCENARIO_REL"
```

**Purpose:** Checks whitespace errors and lists exactly what will be committed.  
**Abnormal output:** Any raw archive, extracted log, SQLite database, Cookie or token-bearing file.  
**Evidence impact:** Read-only.

## 6. Commit and push

```bash
git -C "$REPO_ROOT" commit -m "Complete Scenario 15 SQL injection and WAF correlation investigation"

git -C "$REPO_ROOT" push
```

**Purpose:** Creates and publishes the Scenario 15 commit.  
**Expected output:** A new commit hash followed by a successful remote update.  
**Evidence impact:** Git history and remote repository are modified; local raw evidence is not uploaded because it is ignored.
