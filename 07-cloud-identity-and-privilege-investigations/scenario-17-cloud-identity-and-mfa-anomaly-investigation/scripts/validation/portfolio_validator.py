#!/usr/bin/env python3
"""Validate the publishable Scenario 17 portfolio and local evidence boundaries."""
from __future__ import annotations

import argparse
import os
import subprocess
from pathlib import Path

REQUIRED_DOCS = [
    "README.md", "dataset-decision-record.md", "evidence-inventory.md",
    "source-and-license-record.md", "triage-note.md", "investigation-report.md",
    "recommended-actions.md", "containment-decision-record.md",
    "detection-engineering.md", "false-positive-tuning.md",
]
REQUIRED_PROCESSED = [
    "cloud-identity-event-timeline.csv", "identity-and-signin-type-summary.csv",
    "application-and-resource-summary.csv", "source-ip-and-location-analysis.csv",
    "device-context-analysis.csv", "authentication-result-analysis.csv",
    "mfa-method-and-result-analysis.csv", "conditional-access-analysis.csv",
    "risk-signal-assessment.csv", "correlation-and-session-analysis.csv",
    "legacy-authentication-analysis.csv", "mfa-fatigue-assessment.csv",
    "password-spray-assessment.csv", "follow-on-activity-analysis.csv",
    "account-compromise-assessment.csv", "detection-gap-analysis.csv",
    "sanitised-evidence-excerpts.tsv", "source-sha256-records.tsv",
]
REQUIRED_SCRIPTS = [
    "scripts/acquisition/scenario17_generate_synthetic_dataset.py",
    "scripts/parsing/scenario17_first_pass.py",
    "scripts/analysis/scenario17_precise_verification.py",
    "scripts/analysis/user_baseline.py",
    "scripts/analysis/build_processed_evidence.py",
    "scripts/validation/portfolio_validator.py",
    "scripts/safe-reproducibility-wrapper.sh",
    "scripts/sanitisation/sanitisation_tests.py",
]
FORBIDDEN_FILES = {
    "PACKAGE-MANIFEST.tsv", "executive-summary.md", "github-publishing-guide.md",
    "investigation-notes.md", "remediation-plan.md", "validation-checklist.md",
}
RUNTIME_DIRS = {"__pycache__", ".pytest_cache", ".venv", "venv"}
LOCAL_PREFIXES = ("evidence/raw", "evidence/working")
TEXT_SUFFIXES = {".md", ".txt", ".csv", ".tsv", ".json", ".jsonl", ".yml", ".yaml", ".py", ".sh", ".sql", ".kql", ".spl", ".esql"}
FORBIDDEN_PUBLISHABLE_SUFFIXES = {".zip", ".7z", ".rar", ".gz", ".tgz", ".pcap", ".pcapng", ".sqlite", ".sqlite3", ".db", ".docx", ".xlsx", ".pptx"}


def run_git(repo: Path, *args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(["git", "-C", str(repo), *args], text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)


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


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--scenario-dir", required=True, type=Path)
    ap.add_argument("--repo-root", type=Path)
    ap.add_argument("--mode", choices=("git-aware", "standalone"), default="git-aware")
    args = ap.parse_args()
    scenario = args.scenario_dir.expanduser().resolve()
    failures: list[str] = []

    for rel in REQUIRED_DOCS:
        if not (scenario / rel).is_file(): failures.append(f"missing document: {rel}")
    for rel in REQUIRED_PROCESSED:
        if not (scenario / "evidence/processed" / rel).is_file(): failures.append(f"missing processed evidence: {rel}")
    for rel in REQUIRED_SCRIPTS:
        if not (scenario / rel).is_file(): failures.append(f"missing script: {rel}")
    for rel in FORBIDDEN_FILES:
        if (scenario / rel).exists(): failures.append(f"stale internal artifact remains: {rel}")

    for path in publishable_files(scenario):
        rel = path.relative_to(scenario)
        suffix = path.suffix.lower()
        if suffix in FORBIDDEN_PUBLISHABLE_SUFFIXES:
            failures.append(f"unexpected publishable binary/archive: {rel.as_posix()}")
        if suffix not in TEXT_SUFFIXES:
            continue
        data = path.read_text(encoding="utf-8", errors="replace")
        for number, line in enumerate(data.splitlines(), 1):
            if line.rstrip(" \t") != line:
                failures.append(f"trailing whitespace: {rel.as_posix()}:{number}")
            if line.startswith(("<<<<<<<", "=======", ">>>>>>>")):
                failures.append(f"conflict marker: {rel.as_posix()}:{number}")

    if args.mode == "git-aware":
        if args.repo_root is None:
            failures.append("--repo-root is required in git-aware mode")
        else:
            repo = args.repo_root.expanduser().resolve()
            prefixes = []
            for name in ("raw", "working"):
                directory = scenario / "evidence" / name
                if directory.exists():
                    try: prefixes.append(str(directory.relative_to(repo)))
                    except ValueError: failures.append(f"local evidence outside repo: {directory}")
            if prefixes:
                tracked = run_git(repo, "ls-files", "--", *prefixes)
                for item in tracked.stdout.splitlines():
                    if (repo / item).exists():
                        failures.append(f"local evidence tracked by Git: {item}")
                unignored = run_git(repo, "ls-files", "--others", "--exclude-standard", "--", *prefixes)
                for item in unignored.stdout.splitlines():
                    failures.append(f"local evidence not ignored by Git: {item}")

    if failures:
        print("PORTFOLIO VALIDATION: FAIL")
        for item in failures: print(f"  {item}")
        return 1
    print("PORTFOLIO VALIDATION: PASS")
    print(f"Mode: {args.mode}")
    print(f"Scenario: {scenario}")
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
