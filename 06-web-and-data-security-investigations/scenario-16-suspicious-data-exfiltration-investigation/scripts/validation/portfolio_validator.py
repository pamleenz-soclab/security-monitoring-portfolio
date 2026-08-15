#!/usr/bin/env python3
"""Validate Scenario 16 in git-aware or standalone-package mode."""
from __future__ import annotations

import argparse
import os
import subprocess
from pathlib import Path

REQUIRED = [
    "README.md",
    "dataset-decision-record.md",
    "evidence-inventory.md",
    "source-and-license-record.md",
    "triage-note.md",
    "investigation-report.md",
    "recommended-actions.md",
    "containment-decision-record.md",
    "detection-engineering.md",
    "false-positive-tuning.md",
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
]

FORBIDDEN_SUFFIXES = {
    ".pcap", ".pcapng", ".evtx", ".sqlite", ".sqlite3", ".db",
    ".dump", ".dmp", ".har", ".zip", ".7z", ".rar", ".tar", ".gz", ".tgz",
    ".xlsx", ".xls", ".docx", ".doc", ".pptx", ".ppt",
}
LOCAL_EVIDENCE_DIRS = (Path("evidence/raw"), Path("evidence/working"))
RUNTIME_DIR_NAMES = {"__pycache__", ".venv", "venv", ".pytest_cache"}


def run(cmd: list[str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(cmd, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)


def is_local_evidence(relative_path: Path) -> bool:
    return any(relative_path == base or base in relative_path.parents for base in LOCAL_EVIDENCE_DIRS)


def iter_publishable_files(root: Path):
    for current, dirnames, filenames in os.walk(root):
        current_path = Path(current)
        rel_current = current_path.relative_to(root)
        kept = []
        for dirname in dirnames:
            child_rel = rel_current / dirname
            if is_local_evidence(child_rel) or dirname in RUNTIME_DIR_NAMES:
                continue
            kept.append(dirname)
        dirnames[:] = kept
        for filename in filenames:
            yield current_path / filename


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
    for path in iter_publishable_files(scenario):
        relative = path.relative_to(scenario)
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
            extras = [p for p in directory.rglob("*") if p.is_file()]
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
                local_paths = []
                for directory in (raw, working):
                    try:
                        local_paths.append(str(directory.relative_to(repo)))
                    except ValueError:
                        errors.append(f"local_evidence_outside_repo: {directory}")

                if local_paths:
                    tracked = run(["git", "-C", str(repo), "ls-files", "--", *local_paths])
                    if tracked.stdout.strip():
                        for item in tracked.stdout.splitlines():
                            errors.append(f"local_evidence_tracked: {item}")

                    unignored = run([
                        "git", "-C", str(repo), "ls-files",
                        "--others", "--exclude-standard", "--", *local_paths,
                    ])
                    if unignored.stdout.strip():
                        for item in unignored.stdout.splitlines():
                            errors.append(f"local_evidence_not_ignored: {item}")

    if errors:
        print("\n".join(errors))
        return 1
    print(f"OK: {args.mode} validation passed for {scenario}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
