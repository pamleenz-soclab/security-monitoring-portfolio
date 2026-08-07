#!/usr/bin/env python3
"""Validate Scenario 17 in git-aware or standalone-package mode."""
from __future__ import annotations

import argparse
import csv
import hashlib
import os
import subprocess
from pathlib import Path

REQUIRED_DOCS = [
    "README.md", "dataset-decision-record.md", "evidence-inventory.md",
    "source-and-license-record.md", "triage-note.md", "investigation-notes.md",
    "investigation-report.md", "executive-summary.md", "recommended-actions.md",
    "containment-decision-record.md", "remediation-plan.md",
    "detection-engineering.md", "false-positive-tuning.md",
    "validation-checklist.md", "github-publishing-guide.md",
    "PACKAGE-MANIFEST.tsv",
]
REQUIRED_PROCESSED = [
    "cloud-identity-event-timeline.csv",
    "identity-and-signin-type-summary.csv",
    "application-and-resource-summary.csv",
    "source-ip-and-location-analysis.csv",
    "device-context-analysis.csv",
    "authentication-result-analysis.csv",
    "mfa-method-and-result-analysis.csv",
    "conditional-access-analysis.csv",
    "risk-signal-assessment.csv",
    "correlation-and-session-analysis.csv",
    "legacy-authentication-analysis.csv",
    "mfa-fatigue-assessment.csv",
    "password-spray-assessment.csv",
    "follow-on-activity-analysis.csv",
    "account-compromise-assessment.csv",
    "detection-gap-analysis.csv",
    "sanitised-evidence-excerpts.tsv",
    "source-sha256-records.tsv",
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


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def run_git(repo: Path, *args: str) -> subprocess.CompletedProcess:
    return subprocess.run(
        ["git", "-C", str(repo), *args],
        text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
    )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--scenario-dir", required=True, type=Path)
    parser.add_argument("--repo-root", type=Path)
    parser.add_argument("--mode", choices=("git-aware", "standalone"), default="git-aware")
    args = parser.parse_args()

    scenario = args.scenario_dir.expanduser().resolve()
    failures = []
    warnings = []

    for rel in REQUIRED_DOCS:
        if not (scenario / rel).is_file():
            failures.append(f"missing document: {rel}")
    for name in REQUIRED_PROCESSED:
        if not (scenario / "evidence" / "processed" / name).is_file():
            failures.append(f"missing processed evidence: {name}")
    for rel in REQUIRED_SCRIPTS:
        if not (scenario / rel).is_file():
            failures.append(f"missing script: {rel}")

    text_suffixes = {
        ".md", ".txt", ".csv", ".tsv", ".json", ".jsonl", ".yml", ".yaml",
        ".py", ".sh", ".sql", ".kql", ".spl", ".esql",
    }
    for path in scenario.rglob("*"):
        if not path.is_file() or path.suffix.lower() not in text_suffixes:
            continue
        if "evidence/raw" in path.as_posix() or "evidence/working" in path.as_posix():
            continue
        data = path.read_text(encoding="utf-8", errors="replace")
        for number, line in enumerate(data.splitlines(), 1):
            if line.rstrip(" \t") != line:
                failures.append(f"trailing whitespace: {path.relative_to(scenario)}:{number}")
            if line.startswith(("<<<<<<<", "=======", ">>>>>>>")):
                failures.append(f"conflict marker: {path.relative_to(scenario)}:{number}")

    for name in ("raw", "working"):
        directory = scenario / "evidence" / name
        if not directory.is_dir():
            failures.append(f"missing directory: evidence/{name}")
            continue
        non_keep = [p for p in directory.rglob("*") if p.is_file() and p.name != ".gitkeep"]
        if args.mode == "standalone" and non_keep:
            failures.append(f"standalone evidence/{name} contains local files")
        if args.mode == "git-aware":
            if args.repo_root is None:
                failures.append("--repo-root is required in git-aware mode")
                continue
            repo = args.repo_root.expanduser().resolve()
            for path in non_keep:
                tracked = run_git(repo, "ls-files", "--error-unmatch", str(path))
                if tracked.returncode == 0:
                    failures.append(f"local evidence tracked by Git: {path}")
                ignored = run_git(repo, "check-ignore", "-q", str(path))
                if ignored.returncode != 0:
                    failures.append(f"local evidence not ignored by Git: {path}")

    manifest = scenario / "PACKAGE-MANIFEST.tsv"
    if manifest.is_file():
        with manifest.open("r", encoding="utf-8", newline="") as fh:
            rows = list(csv.DictReader(fh, delimiter="\t"))
        for row in rows:
            rel = row["path"]
            path = scenario / rel
            if not path.is_file():
                failures.append(f"manifest path missing: {rel}")
                continue
            if str(path.stat().st_size) != row["size_bytes"]:
                failures.append(f"manifest size mismatch: {rel}")
            if sha256(path) != row["sha256"]:
                failures.append(f"manifest hash mismatch: {rel}")

    if failures:
        print("PORTFOLIO VALIDATION: FAIL")
        for item in failures:
            print(f"  {item}")
        return 1

    print("PORTFOLIO VALIDATION: PASS")
    print(f"Mode: {args.mode}")
    print(f"Scenario: {scenario}")
    if warnings:
        for item in warnings:
            print(f"WARNING: {item}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
