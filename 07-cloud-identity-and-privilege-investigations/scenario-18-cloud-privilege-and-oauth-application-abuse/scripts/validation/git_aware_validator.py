#!/usr/bin/env python3
"""Validate Git publication boundaries while allowing ignored local raw/working evidence."""

from __future__ import annotations

import argparse
import json
import subprocess
from pathlib import Path

def run(repo: Path, *args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(["git", "-C", str(repo), *args], text=True, capture_output=True)

def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo-root", required=True, type=Path)
    parser.add_argument("--scenario-dir", required=True, type=Path)
    parser.add_argument("--report", required=True, type=Path)
    args = parser.parse_args()

    repo = args.repo_root.resolve()
    scenario = args.scenario_dir.resolve()
    report = args.report.resolve()
    errors = []
    warnings = []

    if not (repo / ".git").exists():
        errors.append(f"Not a Git repository root: {repo}")
    try:
        rel_scenario = scenario.relative_to(repo)
    except ValueError:
        errors.append("Scenario directory is not under repository root")
        rel_scenario = Path(".")

    tracked = run(repo, "ls-files", "--", str(rel_scenario / "evidence/raw"), str(rel_scenario / "evidence/working"))
    tracked_files = [line for line in tracked.stdout.splitlines() if line and not line.endswith(".gitkeep")]
    if tracked_files:
        errors.append("Raw or working evidence is tracked: " + ", ".join(tracked_files))

    for directory in [scenario / "evidence/raw", scenario / "evidence/working"]:
        for path in directory.rglob("*"):
            if not path.is_file() or path.name == ".gitkeep":
                continue
            check = run(repo, "check-ignore", "-q", str(path))
            if check.returncode != 0:
                errors.append(f"Local evidence is not ignored: {path.relative_to(repo)}")

    for path in (scenario / "scripts").rglob("*"):
        if path.is_file():
            check = run(repo, "check-ignore", "-q", str(path))
            if check.returncode == 0:
                errors.append(f"Safe script is incorrectly ignored: {path.relative_to(repo)}")

    status = run(repo, "status", "--short", "--", str(rel_scenario))
    if status.returncode != 0:
        errors.append(status.stderr.strip() or "git status failed")

    result = {
        "status": "PASS" if not errors else "FAIL",
        "repoRoot": str(repo),
        "scenarioDirectory": str(scenario),
        "trackedRawOrWorking": tracked_files,
        "gitStatus": status.stdout.splitlines(),
        "errors": errors,
        "warnings": warnings,
    }
    report.parent.mkdir(parents=True, exist_ok=True)
    report.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps({"status": result["status"], "errors": len(errors), "report": str(report)}, indent=2))
    return 0 if not errors else 1

if __name__ == "__main__":
    raise SystemExit(main())
