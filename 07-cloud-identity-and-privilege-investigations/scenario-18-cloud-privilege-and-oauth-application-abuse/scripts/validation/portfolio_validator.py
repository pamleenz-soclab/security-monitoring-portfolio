#!/usr/bin/env python3
"""Validate Scenario 18 publishable content and Git evidence boundaries."""
from __future__ import annotations

import argparse
import os
import re
import subprocess
from pathlib import Path

REQUIRED_DOCS = [
    "README.md", "dataset-decision-record.md", "evidence-inventory.md",
    "source-and-license-record.md", "triage-note.md", "investigation-report.md",
    "recommended-actions.md", "containment-decision-record.md",
    "revocation-and-recovery-plan.md", "detection-engineering.md",
    "false-positive-tuning.md", "cloud-object-and-id-guide.md",
]
REQUIRED_PROCESSED = [
    "cloud-privilege-event-timeline.csv", "application-and-service-principal-analysis.csv",
    "application-baseline-analysis.csv", "administrator-baseline-analysis.csv",
    "oauth-consent-analysis.csv", "permission-risk-assessment.csv",
    "role-assignment-analysis.csv", "credential-change-analysis.csv",
    "service-principal-signin-analysis.csv", "api-and-resource-activity-analysis.csv",
    "precise-cloud-privilege-correlation.csv", "owner-verification-analysis.csv",
    "cloud-privilege-abuse-assessment.csv", "detection-gap-analysis.csv",
    "sanitised-evidence-excerpts.tsv", "source-sha256-records.tsv",
]
REQUIRED_CODE = [
    "scripts/generation/generate_synthetic_event.py",
    "scripts/validation/validate_synthetic_package.py",
    "scripts/parsing/first_pass_parser.py",
    "scripts/correlation/precise_cloud_privilege_correlation.py",
    "scripts/correlation/permission_risk.py",
    "scripts/validation/sanitisation_test.py",
    "scripts/validation/portfolio_validator.py",
    "scripts/safe-reproducibility-wrapper.sh",
    "detections/sentinel/04-credential-followed-by-service-principal-signin.kql",
    "detections/sentinel/05-application-permission-followed-by-sensitive-graph-use.kql",
    "detections/generic/cloud-privilege-detection-catalog.yml",
]
FORBIDDEN_TRACKED = {
    "PACKAGE-MANIFEST.tsv", "README-STAGE2.md", "executive-summary.md",
    "github-publishing-guide.md", "interview-walkthrough.md", "investigation-notes.md",
    "validation-checklist.md", "scenario18.gitignore.template", "screenshots/.gitkeep",
    "evidence/raw/.gitkeep", "evidence/working/.gitkeep", "evidence/processed/.gitkeep",
    "scripts/validation/git_aware_validator.py", "scripts/validation/sanitise_processed_evidence.py",
}
LOCAL_PREFIXES = ("evidence/raw", "evidence/working")
RUNTIME_DIRS = {"__pycache__", ".pytest_cache", ".venv", "venv"}
TEXT_SUFFIXES = {".md", ".txt", ".csv", ".tsv", ".json", ".jsonl", ".yml", ".yaml", ".py", ".sh", ".sql", ".kql", ".spl", ".esql"}
USER_PATH = re.compile(r"(?:/Users/[^/\s]+|[A-Za-z]:\\\\Users\\\\[^\\\\\s]+)")


def is_local(rel: Path) -> bool:
    posix = rel.as_posix()
    return any(posix == p or posix.startswith(p + "/") for p in LOCAL_PREFIXES)


def publishable_files(root: Path):
    for current, dirs, files in os.walk(root):
        current_path = Path(current)
        rel_current = current_path.relative_to(root)
        kept = []
        for d in dirs:
            child = rel_current / d
            if d in RUNTIME_DIRS or is_local(child):
                continue
            kept.append(d)
        dirs[:] = kept
        for name in files:
            yield current_path / name


def git(repo: Path, *args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(["git", "-C", str(repo), *args], text=True, capture_output=True)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--scenario-dir", required=True, type=Path)
    ap.add_argument("--repo-root", type=Path)
    args = ap.parse_args()
    root = args.scenario_dir.expanduser().resolve()
    errors: list[str] = []

    for rel in REQUIRED_DOCS + [f"evidence/processed/{x}" for x in REQUIRED_PROCESSED] + REQUIRED_CODE:
        if not (root / rel).is_file():
            errors.append(f"missing_required_file: {rel}")

    for rel in FORBIDDEN_TRACKED:
        if (root / rel).exists():
            errors.append(f"stale_publishable_artifact_present: {rel}")

    for path in publishable_files(root):
        rel = path.relative_to(root).as_posix()
        if path.suffix.lower() not in TEXT_SUFFIXES:
            continue
        try:
            text = path.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            errors.append(f"unexpected_binary_publishable_file: {rel}")
            continue
        for line_no, line in enumerate(text.splitlines(), 1):
            if line.rstrip() != line:
                errors.append(f"trailing_whitespace: {rel}:{line_no}")
        if rel not in {"scripts/validation/portfolio_validator.py", "scripts/validation/sanitisation_test.py"} and USER_PATH.search(text):
            errors.append(f"hard_coded_local_user_path: {rel}")

    if args.repo_root:
        repo = args.repo_root.expanduser().resolve()
        try:
            rel_root = root.relative_to(repo).as_posix()
        except ValueError:
            errors.append("scenario_not_under_repo_root")
            rel_root = ""

        if rel_root:
            local_paths = [f"{rel_root}/evidence/raw", f"{rel_root}/evidence/working"]
            tracked = git(repo, "ls-files", "--", *local_paths)
            if tracked.stdout.strip():
                for item in tracked.stdout.splitlines():
                    errors.append(f"local_evidence_tracked: {item}")

            unignored = git(repo, "ls-files", "--others", "--exclude-standard", "--", *local_paths)
            if unignored.stdout.strip():
                for item in unignored.stdout.splitlines():
                    errors.append(f"local_evidence_not_ignored: {item}")

            tracked_scenario = git(repo, "ls-files", "--", rel_root)
            for item in tracked_scenario.stdout.splitlines():
                p = repo / item
                if p.is_file() and p.stat().st_size > 5 * 1024 * 1024:
                    errors.append(f"unexpected_large_tracked_file: {item}")

    if errors:
        print("FAIL")
        for error in errors:
            print(" -", error)
        return 1

    mode = "Git-aware" if args.repo_root else "publishable"
    print(f"PASS: Scenario 18 {mode} portfolio validation completed with zero errors")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
