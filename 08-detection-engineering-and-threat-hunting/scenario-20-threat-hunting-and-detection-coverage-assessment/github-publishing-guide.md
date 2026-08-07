# GitHub Publishing Guide

## 1. Copy the final package into Scenario 20

Merge the downloaded package into:

```text
08-detection-engineering-and-threat-hunting/
scenario-20-threat-hunting-and-detection-coverage-assessment/
```

Do not delete the local `evidence/working/` directory before you have completed your own archive/review, but do not publish it.

## 2. Confirm ignored/local evidence

```bash
git status --short   "08-detection-engineering-and-threat-hunting/scenario-20-threat-hunting-and-detection-coverage-assessment"
```

Purpose: review exactly what Git sees for Scenario 20.

Expected public artifacts are Markdown files plus `evidence/processed/`. `evidence/working/`, ZIP bundles, and raw evidence should not be staged.

## 3. Validate whitespace

```bash
git diff --check
```

Purpose: identify whitespace errors before staging.

## 4. Stage only the final scenario artifacts

```bash
git add   "08-detection-engineering-and-threat-hunting/scenario-20-threat-hunting-and-detection-coverage-assessment/.gitignore"   "08-detection-engineering-and-threat-hunting/scenario-20-threat-hunting-and-detection-coverage-assessment/"*.md   "08-detection-engineering-and-threat-hunting/scenario-20-threat-hunting-and-detection-coverage-assessment/evidence/processed"
```

Purpose: stage public documentation and processed evidence without staging local working evidence.

## 5. Review the staged set

```bash
git diff --cached --name-only --   "08-detection-engineering-and-threat-hunting/scenario-20-threat-hunting-and-detection-coverage-assessment"

git diff --cached --check
```

Purpose: verify the exact publish set and whitespace quality.

## 6. Commit

```bash
git commit -m "Complete Scenario 20 threat hunting and detection coverage assessment"
```

## 7. Push

```bash
git push
```

Before committing, confirm that `evidence/working/` and any local ZIP files are absent from the staged file list.
