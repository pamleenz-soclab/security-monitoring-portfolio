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
    "investigation-report.md",
    "recommended-actions.md",
    "detection-engineering.md",
    "false-positive-tuning.md",
    "detections/generic/correlation-rules.md",
    "detections/sigma/waf_high_confidence_sqli_request.yml",
    "detections/sigma/waf_rule_942100_password_cookie_context_review.yml",
    "detections/sigma/waf_time_based_sqli.yml",
    "queries/generic/field-mapping.md",
    "queries/sentinel/sqli-burst-threshold.kql",
    "queries/sentinel/sqli-multi-rule-correlation.kql",
    "queries/sentinel/waf-disposition-validation.kql",
    "queries/splunk/sqli-burst-threshold.spl",
    "queries/splunk/sqli-multi-rule-correlation.spl",
    "queries/splunk/waf-disposition-validation.spl",
    "queries/elastic/sqli-burst-threshold.esql",
    "queries/elastic/sqli-multi-rule-correlation.esql",
    "queries/elastic/waf-disposition-validation.esql",
    "evidence/processed/event-summary.tsv",
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
    "evidence/processed/false-positive-examples.csv",
    "evidence/processed/source-sha256-records.tsv",
    "scripts/acquire-dataset.sh",
    "scripts/safe_extract_zip.py",
    "scripts/parse_modsec_audit.py",
    "scripts/run-first-pass.sh",
    "scripts/precise_validate.py",
    "scripts/run-precise-validation.sh",
    "scripts/build_reproduction_sample.py",
    "scripts/portfolio_validator.py",
    "scripts/reproduce-safe.sh",
    "scripts/tests/test_sanitisation.py",
]

PROTECTED_DIRS = (Path("evidence/raw"), Path("evidence/working"))
FORBIDDEN_SUFFIXES = {".zip", ".pcap", ".pcapng", ".sqlite", ".db", ".dump"}
TEXT_SUFFIXES = {
    ".md", ".txt", ".tsv", ".csv", ".yml", ".yaml",
    ".py", ".sh", ".kql", ".spl", ".esql",
}
SECRET_PATTERNS = [
    re.compile(rb"(?im)^Cookie:\s*(?!\[REDACTED\])\S+"),
    re.compile(rb"(?im)^Authorization:\s*(?!\[REDACTED\])\S+"),
    re.compile(rb"(?i)bearer\s+[A-Za-z0-9._~+/-]{16,}"),
]
LOCAL_PATH_PATTERNS = [re.compile(rb"/(?:Users|home)/[A-Za-z0-9._-]+/")]
MAX_PUBLISHABLE_SIZE = 20 * 1024 * 1024


def run_git(top: Path, args: list[str]) -> list[str]:
    output = subprocess.check_output(
        ["git", "-C", str(top), *args], text=True, stderr=subprocess.DEVNULL
    )
    return [line for line in output.splitlines() if line]


def is_protected(rel: Path) -> bool:
    return any(rel == protected or protected in rel.parents for protected in PROTECTED_DIRS)


def validate_protected_package(root: Path, errors: list[str]) -> None:
    """Strict distribution mode: raw/working paths must contain no files."""
    for protected in PROTECTED_DIRS:
        path = root / protected
        if not path.exists():
            continue
        for item in path.rglob("*"):
            if item.is_file():
                errors.append(f"protected local evidence included: {item.relative_to(root)}")


def validate_protected_git_aware(root: Path, errors: list[str]) -> None:
    """Repository mode: raw/working files may exist locally only when ignored and untracked."""
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
            top, ["ls-files", "--others", "--exclude-standard", "--", *protected_specs]
        )
    except subprocess.CalledProcessError:
        errors.append("unable to inspect protected paths with Git")
        return

    for path in tracked:
        errors.append(f"protected local evidence is tracked by Git: {path}")
    for path in unignored_untracked:
        errors.append(f"raw/working path is not ignored: {path}")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("scenario_dir", type=Path)
    modes = parser.add_mutually_exclusive_group()
    modes.add_argument("--git-aware", action="store_true")
    modes.add_argument("--local-reproduction", action="store_true")
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
    elif not args.local_reproduction:
        validate_protected_package(root, errors)

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
            for pattern in LOCAL_PATH_PATTERNS:
                if pattern.search(data):
                    errors.append(f"hard-coded local user path in {rel}")

    if errors:
        print("FAIL")
        for error in errors:
            print(" -", error)
        return 1

    if args.git_aware:
        mode = "Git-aware repository"
    elif args.local_reproduction:
        mode = "local reproduction"
    else:
        mode = "publishable package"
    print(f"PASS: Scenario 15 {mode} validation completed with zero errors")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
