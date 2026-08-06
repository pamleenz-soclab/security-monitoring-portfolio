# GitHub Publishing Guide

The following commands assume the package has been copied into:

```text
/Users/pamlee/Documents/GitHub/security-monitoring-portfolio/05-endpoint-and-windows-investigations/scenario-14-ransomware-early-indicators-and-containment
```

## 1. Re-establish paths in a new terminal

```bash
export REPO_ROOT="/Users/pamlee/Documents/GitHub/security-monitoring-portfolio"
export SCENARIO_DIR="$REPO_ROOT/05-endpoint-and-windows-investigations/scenario-14-ransomware-early-indicators-and-containment"
export RAW_DIR="$SCENARIO_DIR/evidence/raw"
export WORKING_DIR="$SCENARIO_DIR/evidence/working"
```

**Purpose:** Defines the repository, scenario, raw-evidence, and working-evidence paths for the current terminal.

**Important parameters:** These variables are shell-session specific. Re-run them in every new terminal.

## 2. Review all publishable files

```bash
git -C "$REPO_ROOT" status \
  --short \
  --untracked-files=all \
  -- "$SCENARIO_DIR"
```

**Purpose:** Lists every changed or untracked file under Scenario 14.

**Important parameters:**

- `-C "$REPO_ROOT"` runs Git from the repository root.
- `--short` uses compact status output.
- `--untracked-files=all` expands untracked directories.
- `-- "$SCENARIO_DIR"` limits the review to Scenario 14.

The output must not contain raw logs, SQLite databases, malware samples, EVTX, PCAP, ZIP, or Python cache files.

## 3. Confirm raw and working evidence is ignored

```bash
git -C "$REPO_ROOT" check-ignore -v \
  "$RAW_DIR/windows-sysmon.log" \
  "$RAW_DIR/windows-security.log" \
  "$RAW_DIR/windows-powershell.log" \
  "$WORKING_DIR/scenario14-events.sqlite"
```

**Purpose:** Proves that original evidence and the local database are excluded from Git.

**Important parameter:** `-v` displays the exact `.gitignore` rule that matched each path.

Every path should produce an ignore result.

## 4. Search for prohibited file types

```bash
find "$SCENARIO_DIR" -type f \( \
  -name '*.exe' -o \
  -name '*.dll' -o \
  -name '*.sys' -o \
  -name '*.evtx' -o \
  -name '*.pcap' -o \
  -name '*.pcapng' -o \
  -name '*.zip' -o \
  -name '*.7z' -o \
  -name '*.pyc' \
\) -print
```

**Purpose:** Finds dangerous, raw, large, or temporary file types before staging.

**Expected output:** No output.

## 5. Stage only Scenario 14

```bash
git -C "$REPO_ROOT" add -- "$SCENARIO_DIR"
```

**Purpose:** Stages the Scenario 14 portfolio files without staging unrelated repository changes.

**Important parameter:** `--` ends Git options and treats the following value as a path.

## 6. Validate staged content

```bash
git -C "$REPO_ROOT" diff --cached --check
```

**Purpose:** Checks staged files for whitespace errors and malformed conflict markers.

**Expected output:** No output.

```bash
git -C "$REPO_ROOT" diff \
  --cached \
  --name-only \
  -- "$SCENARIO_DIR"
```

**Purpose:** Lists exactly which Scenario 14 files will be committed.

**Important parameters:**

- `--cached` examines the staging area.
- `--name-only` prints filenames without full diffs.

Review the complete list before committing.

## 7. Commit

```bash
git -C "$REPO_ROOT" commit \
  -m "Complete Scenario 14 ransomware precursor and containment investigation"
```

**Purpose:** Creates a commit for the completed Scenario 14 portfolio.

**Important parameter:** `-m` supplies the commit message.

The wording uses **ransomware precursor and containment investigation** because successful content encryption was not independently confirmed.

## 8. Push

```bash
git -C "$REPO_ROOT" push
```

**Purpose:** Pushes the current branch and new commit to the configured remote repository.

Before pushing, confirm the commit summary contains no raw evidence or prohibited files.

## 9. Final verification

```bash
git -C "$REPO_ROOT" status --short
git -C "$REPO_ROOT" log -1 --oneline
```

**Purpose:** Confirms the working tree state and displays the latest commit.

A clean status means no uncommitted files remain outside intentionally ignored raw and working evidence.
