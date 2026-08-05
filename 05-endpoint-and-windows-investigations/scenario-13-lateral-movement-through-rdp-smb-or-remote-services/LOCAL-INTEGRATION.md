# Local Integration Steps

The final archive is designed to be extracted at the repository root. It adds the Scenario 13 directory without including raw or working evidence.

## 1. Extract at the repository root

```bash
REPO_ROOT="/Users/pamlee/Documents/GitHub/security-monitoring-portfolio"
PACKAGE="$HOME/Downloads/scenario-13-final-package.zip"

unzip -o "$PACKAGE" -d "$REPO_ROOT"
```

Purpose: merge the reviewed Scenario 13 package into the existing repository.

Important parameters:

- `-o` replaces existing Scenario 13 portfolio files without interactive prompts.
- `-d "$REPO_ROOT"` places the included `05-endpoint-and-windows-investigations/...` path correctly.
- Raw logs are not present in the package and are not overwritten.

## 2. Prepare the selected dataset

```bash
SCENARIO_DIR="$REPO_ROOT/05-endpoint-and-windows-investigations/scenario-13-lateral-movement-through-rdp-smb-or-remote-services"

cd "$SCENARIO_DIR" || exit 1
bash scripts/prepare_dataset.sh
```

Purpose: preserve the known rejected candidate, download pinned OTRF archives, verify SHA-256 values and extract one host JSON plus two PCAPs under ignored raw directories.

## 3. Reproduce processed evidence

```bash
bash scripts/run_analysis.sh
```

Expected final lines:

```text
Validated 7504 host events and 2 PCAPs
Wrote 12 processed evidence files
Verdict: True Positive - successful SMB remote service execution as SYSTEM
```

## 4. Verify Git protection

```bash
find evidence/raw evidence/working \\
  -type f \\
  ! -name '.gitkeep' \\
  -print0 | xargs -0 git check-ignore -v

git status --short --untracked-files=all .
```

Purpose: confirm that raw JSON, PCAPs, archives and working files remain ignored while documentation, scripts, detections and processed summaries are visible to Git.

## 5. Run final safety checks

```bash
python3 -m json.tool evidence/processed/analysis-summary.json >/dev/null

find . \( -name '__pycache__' -o -name '*.pyc' \) -print

grep -RInE \\
  --exclude-dir=raw \\
  --exclude-dir=working \\
  --exclude-dir=.git \\
  '(-enc[[:space:]]+[A-Za-z0-9+/=]{80,}|[A-Fa-f0-9]{32}:[A-Fa-f0-9]{32})' \\
  . || true

git diff --check
```

Expected results:

- JSON validation succeeds.
- The `find` command prints nothing.
- No full encoded payload or credential material is returned.
- `git diff --check` prints nothing.
