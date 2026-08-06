#!/usr/bin/env python3
"""Validate Scenario 16 in git-aware or standalone-package mode."""
from __future__ import annotations

import argparse
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
    "containment-decision-record.md",
    "remediation-plan.md",
    "detection-engineering.md",
    "false-positive-tuning.md",
    "validation-checklist.md",
    "github-publishing-guide.md",
    "PACKAGE-MANIFEST.tsv",
    "evidence/processed/exfiltration-event-timeline.csv",
    "evidence/processed/source-host-account-process-summary.csv",
    "evidence/processed/destination-and-domain-summary.csv",
    "evidence/processed/network-flow-and-volume-analysis.csv",
    "evidence/processed/process-to-network-correlation.csv",
    "evidence/processed/file-collection-and-staging-analysis.csv",
    "evidence/processed/compression-and-encryption-analysis.csv",
    "evidence/processed/dns-tunnelling-analysis.csv",
    "evidence/processed/cloud-and-web-upload-analysis.csv",
    "evidence/processed/transfer-outcome-assessment.csv",
    "evidence/processed/data-scope-assessment.csv",
    "evidence/processed/follow-on-cleanup-analysis.csv",
    "evidence/processed/detection-gap-analysis.csv",
    "evidence/processed/sanitised-evidence-excerpts.tsv",
    "evidence/processed/source-sha256-records.tsv",
]

FORBIDDEN_SUFFIXES = {
    ".pcap", ".pcapng", ".evtx", ".sqlite", ".sqlite3", ".db",
    ".dump", ".dmp", ".har", ".zip", ".7z", ".rar", ".tar",
}
LOCAL_EVIDENCE_DIRS = (Path("evidence/raw"), Path("evidence/working"))


def run(cmd: list[str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(cmd, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)


def is_local_evidence(relative_path: Path) -> bool:
    return any(relative_path == base or base in relative_path.parents for base in LOCAL_EVIDENCE_DIRS)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--scenario", required=True)
    parser.add_argument("--mode", choices=["git-aware", "standalone"], required=True)
    parser.add_argument("--repo-root")
    args = parser.parse_args()

    scenario = Path(args.scenario).expanduser().resolve()
    errors: list[str] = []

    if not scenario.is_dir():
        print(f"scenario_not_found: {scenario}")
        return 1

    for relative in REQUIRED:
        path = scenario / relative
        if not path.is_file() or path.stat().st_size == 0:
            errors.append(f"missing_or_empty: {relative}")

    left = "<" * 7
    right = ">" * 7
    for path in scenario.rglob("*"):
        if not path.is_file():
            continue
        relative = path.relative_to(scenario)
        if is_local_evidence(relative):
            continue
        if path.suffix.lower() in FORBIDDEN_SUFFIXES:
            errors.append(f"forbidden_publishable_file: {relative}")
        text = path.read_text(encoding="utf-8", errors="ignore") if path.stat().st_size < 5_000_000 else ""
        if left in text or right in text:
            errors.append(f"conflict_marker: {relative}")
        for line_number, line in enumerate(text.splitlines(), 1):
            if line.rstrip() != line:
                errors.append(f"trailing_whitespace: {relative}:{line_number}")

    raw = scenario / "evidence/raw"
    working = scenario / "evidence/working"

    if args.mode == "standalone":
        for directory in (raw, working):
            extras = [p for p in directory.rglob("*") if p.is_file() and p.name != ".gitkeep"]
            if extras:
                errors.append(f"standalone_local_evidence_present: {directory}")
    else:
        if not args.repo_root:
            errors.append("git-aware requires --repo-root")
        else:
            repo = Path(args.repo_root).expanduser().resolve()
            if not (repo / ".git").exists():
                errors.append(f"repo_root_not_git_repository: {repo}")
            else:
                try:
                    scenario.relative_to(repo)
                except ValueError:
                    errors.append(f"scenario_outside_repo: {scenario}")
                for directory in (raw, working):
                    for path in directory.rglob("*"):
                        if not path.is_file() or path.name == ".gitkeep":
                            continue
                        try:
                            relative_to_repo = path.relative_to(repo)
                        except ValueError:
                            errors.append(f"local_evidence_outside_repo: {path}")
                            continue
                        tracked = run([
                            "git", "-C", str(repo), "ls-files", "--error-unmatch", "--",
                            str(relative_to_repo),
                        ])
                        ignored = run([
                            "git", "-C", str(repo), "check-ignore", "-q", "--no-index", "--",
                            str(relative_to_repo),
                        ])
                        if tracked.returncode == 0:
                            errors.append(f"local_evidence_tracked: {relative_to_repo}")
                        if ignored.returncode != 0:
                            errors.append(f"local_evidence_not_ignored: {relative_to_repo}")

    if errors:
        print("\n".join(errors))
        return 1
    print(f"OK: {args.mode} validation passed for {scenario}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
