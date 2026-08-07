#!/usr/bin/env python3
from __future__ import annotations
import argparse, csv, subprocess
from pathlib import Path

SCENARIO_REL = Path("09-enterprise-incident-response-and-capstone/scenario-21-enterprise-compromise-investigation")

REQUIRED = [
    "README.md","scenario-scope.md","incident-overview.md","executive-summary.md",
    "technical-investigation-report.md","investigation-methodology.md","evidence-inventory.md",
    "entity-analysis.md","master-timeline.md","correlation-analysis.md","attack-stage-assessment.md",
    "attack-chain-reconstruction.md","scope-assessment.md","impact-assessment.md",
    "ioc-and-observable-analysis.md","containment-strategy.md","recovery-validation.md",
    "detection-coverage-assessment.md","logging-and-visibility-gaps.md",
    "detection-improvement-backlog.md","investigation-limitations.md","lessons-learned.md",
    "interview-walkthrough.md","validation-checklist.md","source-and-license-record.md",
    "github-publishing-guide.md","PACKAGE-MANIFEST.tsv",
    "evidence/processed/incident-lead-register.csv",
    "evidence/processed/evidence-inventory.csv",
    "evidence/processed/entity-inventory.csv",
    "evidence/processed/entity-relationship-map.csv",
    "evidence/processed/master-timeline.csv",
    "evidence/processed/correlation-matrix.csv",
    "evidence/processed/attack-stage-assessment.csv",
    "evidence/processed/attack-mapping.csv",
    "evidence/processed/scope-assessment.csv",
    "evidence/processed/impact-assessment.csv",
    "evidence/processed/ioc-observable-register.csv",
    "evidence/processed/containment-decision-register.csv",
    "evidence/processed/recovery-validation-matrix.csv",
    "evidence/processed/detection-coverage-matrix.csv",
    "evidence/processed/logging-visibility-gap-register.csv",
    "evidence/processed/detection-improvement-backlog.csv",
    "evidence/processed/investigation-limitations.csv",
    "evidence/processed/sanitised-evidence-excerpts.tsv",
    "evidence/processed/source-sha256-records.tsv",
]

FORBIDDEN_OVERCLAIMS = [
    "initial access confirmed",
    "certificate theft was successful",
    "confirmed successful exfiltration",
    "zeek corroborated the same event",
    "zeek confirmed the host event",
]

def run(cmd, cwd):
    return subprocess.run(cmd, cwd=cwd, text=True, capture_output=True)

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--repo-root", required=True)
    args = ap.parse_args()

    repo = Path(args.repo_root).resolve()
    scen = repo / SCENARIO_REL
    errors, warnings = [], []

    for rel in REQUIRED:
        if not (scen / rel).exists():
            errors.append(f"Missing required artifact: {rel}")

    for p in scen.rglob("*.md"):
        if "raw" in p.parts or "working" in p.parts:
            continue
        txt = p.read_text(encoding="utf-8", errors="replace").lower()
        for phrase in FORBIDDEN_OVERCLAIMS:
            if phrase in txt:
                errors.append(f"Overclaim phrase '{phrase}' in {p.relative_to(scen)}")

    stage = scen / "evidence/processed/attack-stage-assessment.csv"
    if stage.exists():
        with stage.open(encoding="utf-8") as f:
            rows = {r["attack_stage"]: r for r in csv.DictReader(f)}
        expected = {
            "Initial Access":"Not available / Unable to assess",
            "Execution":"Observed",
            "Discovery":"Not observed in the incident chain",
            "Exfiltration":"Not observed / Unable to assess",
            "Impact":"Not observed",
        }
        for stage_name, expected_status in expected.items():
            actual = rows.get(stage_name, {}).get("status")
            if actual != expected_status:
                errors.append(f"{stage_name}: {actual!r}; expected {expected_status!r}")

    if (repo / ".git").exists():
        tracked = run(["git","ls-files","--",str(SCENARIO_REL)], repo)
        if tracked.returncode == 0:
            for line in tracked.stdout.splitlines():
                normalized = line.replace("\\", "/")
                allowed_raw_placeholder = normalized.endswith("/evidence/raw/.gitkeep")
                if ("/evidence/raw/" in f"/{normalized}" or "/evidence/working/" in f"/{normalized}") and not allowed_raw_placeholder:
                    errors.append(f"Raw/working evidence is Git-tracked: {line}")

        status = run(["git","status","--short","--untracked-files=all","--",str(SCENARIO_REL)], repo)
        if status.returncode == 0:
            for line in status.stdout.splitlines():
                path = line[3:] if len(line) > 3 else line
                normalized = path.replace("\\", "/")
                allowed_raw_placeholder = normalized.endswith("/evidence/raw/.gitkeep")
                if ("/evidence/raw/" in f"/{normalized}" or "/evidence/working/" in f"/{normalized}") and not allowed_raw_placeholder:
                    warnings.append(f"Raw/working path appears in git status: {line}")

        diff = run(["git","diff","--check"], repo)
        if diff.stdout.strip():
            warnings.append("git diff --check reported whitespace/errors; review before staging.")

    for p in scen.rglob("*"):
        if p.is_file() and "raw" not in p.parts and "working" not in p.parts and p.stat().st_size > 10*1024*1024:
            warnings.append(f"Large publishable file >10 MiB: {p.relative_to(scen)}")

    print("SCENARIO 21 — FINAL VALIDATOR")
    print(f"Errors: {len(errors)}")
    print(f"Warnings: {len(warnings)}")
    for e in errors:
        print("ERROR:", e)
    for w in warnings:
        print("WARN:", w)

    if errors:
        print("RESULT: FAIL")
        return 1

    print("RESULT: PASS")
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
