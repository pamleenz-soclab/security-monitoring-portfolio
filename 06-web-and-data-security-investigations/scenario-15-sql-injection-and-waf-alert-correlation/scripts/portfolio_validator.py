#!/usr/bin/env python3
from __future__ import annotations

import argparse
import re
import subprocess
from pathlib import Path

REQUIRED = [
    "README.md",
    "dataset-decision-record.md",
    "evidence-inventory.md",
    "source-and-license-record.md",
    "triage-note.md",
    "investigation-notes.md",
    "investigation-report.md",
    "executive-summary.md",
    "recommended-actions.md",
    "remediation-plan.md",
    "detection-engineering.md",
    "false-positive-tuning.md",
    "validation-checklist.md",
    "github-publishing-guide.md",
    "PACKAGE-MANIFEST.tsv",
    "evidence/processed/web-request-timeline.csv",
    "evidence/processed/waf-alert-summary.csv",
    "evidence/processed/waf-and-server-correlation.csv",
    "evidence/processed/request-outcome-assessment.csv",
    "evidence/processed/source-ip-and-user-agent-summary.csv",
    "evidence/processed/encoding-and-normalisation-analysis.csv",
    "evidence/processed/application-and-database-evidence.csv",
    "evidence/processed/follow-on-activity-analysis.csv",
    "evidence/processed/detection-gap-analysis.csv",
    "evidence/processed/sanitised-evidence-excerpts.tsv",
    "evidence/processed/source-sha256-records.tsv",
    "scripts/parse_modsec_audit.py",
    "scripts/precise_validate.py",
    "scripts/portfolio_validator.py",
    "scripts/reproduce-safe.sh",
]

PROTECTED_DIRS = (Path("evidence/raw"), Path("evidence/working"))
FORBIDDEN_SUFFIXES = {".zip", ".pcap", ".pcapng", ".sqlite", ".db", ".dump"}
TEXT_SUFFIXES = {
    ".md",
    ".txt",
    ".tsv",
    ".csv",
    ".yml",
    ".yaml",
    ".py",
    ".sh",
    ".kql",
    ".spl",
    ".esql",
}
SECRET_PATTERNS = [
    re.compile(rb"(?im)^Cookie:\s*(?!\[REDACTED\])\S+"),
    re.compile(rb"(?im)^Authorization:\s*(?!\[REDACTED\])\S+"),
    re.compile(rb"(?i)bearer\s+[A-Za-z0-9._~+/-]{16,}"),
]
MAX_PUBLISHABLE_SIZE = 20 * 1024 * 1024


def run_git(top: Path, args: list[str]) -> list[str]:
    output = subprocess.check_output(
        ["git", "-C", str(top), *args],
        text=True,
        stderr=subprocess.DEVNULL,
    )
    return [line for line in output.splitlines() if line]


def is_protected(rel: Path) -> bool:
    return any(rel == protected or protected in rel.parents for protected in PROTECTED_DIRS)


def validate_protected_non_git(root: Path, errors: list[str]) -> None:
    """Package/distribution mode: protected directories may contain only .gitkeep."""
    for protected in PROTECTED_DIRS:
        path = root / protected
        if not path.exists():
            continue
        for item in path.rglob("*"):
            if item.is_file() and item.name != ".gitkeep":
                errors.append(f"protected local evidence included: {item.relative_to(root)}")


def validate_protected_git_aware(root: Path, errors: list[str]) -> None:
    """Repository mode: local raw/working files are allowed only when untracked and ignored."""
    try:
        top = Path(
            subprocess.check_output(
                ["git", "-C", str(root), "rev-parse", "--show-toplevel"],
                text=True,
                stderr=subprocess.DEVNULL,
            ).strip()
        ).resolve()
    except subprocess.CalledProcessError:
        errors.append("--git-aware requested but scenario is not inside a Git repository")
        return

    try:
        scenario_rel = root.relative_to(top)
    except ValueError:
        errors.append("scenario directory is outside the detected Git worktree")
        return

    protected_specs = [str(scenario_rel / protected) for protected in PROTECTED_DIRS]

    try:
        tracked = run_git(top, ["ls-files", "--", *protected_specs])
        unignored_untracked = run_git(
            top,
            ["ls-files", "--others", "--exclude-standard", "--", *protected_specs],
        )
    except subprocess.CalledProcessError:
        errors.append("unable to inspect protected paths with Git")
        return

    for path in tracked:
        if Path(path).name != ".gitkeep":
            errors.append(f"protected local evidence is tracked by Git: {path}")

    for path in unignored_untracked:
        if Path(path).name != ".gitkeep":
            errors.append(f"raw/working path is not ignored: {path}")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("scenario_dir", type=Path)
    parser.add_argument("--git-aware", action="store_true")
    args = parser.parse_args()

    root = args.scenario_dir.resolve()
    errors: list[str] = []

    if not root.is_dir():
        print("FAIL")
        print(f" - scenario directory not found: {root}")
        return 1

    for rel in REQUIRED:
        if not (root / rel).exists():
            errors.append(f"missing required file: {rel}")

    if args.git_aware:
        validate_protected_git_aware(root, errors)
    else:
        validate_protected_non_git(root, errors)

    # Protected local evidence is intentionally excluded from publishable-content
    # checks. In --git-aware mode, the Git checks above verify it is neither tracked
    # nor accidentally unignored. In package mode, only .gitkeep is permitted there.
    for item in root.rglob("*"):
        if not item.is_file():
            continue

        rel = item.relative_to(root)
        if is_protected(rel):
            continue

        if item.suffix.lower() in FORBIDDEN_SUFFIXES:
            errors.append(f"forbidden artefact: {rel}")

        if item.stat().st_size > MAX_PUBLISHABLE_SIZE:
            errors.append(f"oversized publishable file: {rel}")

        if item.suffix.lower() in TEXT_SUFFIXES:
            data = item.read_bytes()
            for pattern in SECRET_PATTERNS:
                if pattern.search(data):
                    errors.append(f"possible secret/header value in {rel}")

    if errors:
        print("FAIL")
        for error in errors:
            print(" -", error)
        return 1

    mode = "Git-aware repository" if args.git_aware else "publishable package"
    print(f"PASS: Scenario 15 {mode} validation completed with zero errors")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
