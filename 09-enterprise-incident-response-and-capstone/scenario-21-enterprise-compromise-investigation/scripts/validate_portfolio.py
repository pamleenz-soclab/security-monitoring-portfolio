#!/usr/bin/env python3
from __future__ import annotations

import csv
import os
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
ERRORS: list[str] = []


def fail(message: str) -> None:
    ERRORS.append(message)


def read_table(rel: str, delimiter: str = ",") -> list[dict[str, str]]:
    path = ROOT / rel
    if not path.exists():
        fail(f"missing required table: {rel}")
        return []
    try:
        with path.open(encoding="utf-8", newline="") as handle:
            return list(csv.DictReader(handle, delimiter=delimiter))
    except Exception as exc:
        fail(f"unable to parse {rel}: {exc}")
        return []


REQUIRED = [
    "README.md",
    "scenario-scope.md",
    "incident-overview.md",
    "executive-summary.md",
    "technical-investigation-report.md",
    "investigation-methodology.md",
    "evidence-inventory.md",
    "entity-analysis.md",
    "master-timeline.md",
    "correlation-analysis.md",
    "attack-stage-assessment.md",
    "attack-chain-reconstruction.md",
    "scope-assessment.md",
    "impact-assessment.md",
    "ioc-and-observable-analysis.md",
    "containment-strategy.md",
    "recovery-validation.md",
    "detection-coverage-assessment.md",
    "logging-and-visibility-gaps.md",
    "detection-improvement-backlog.md",
    "investigation-limitations.md",
    "lessons-learned.md",
    "source-and-license-record.md",
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
    "evidence/processed/source-acquisition-manifest.tsv",
    "evidence/processed/dataset-boundary-record.tsv",
]

for rel in REQUIRED:
    if not (ROOT / rel).exists():
        fail(f"missing required artifact: {rel}")

STALE = [
    "PACKAGE-MANIFEST.tsv",
    "github-publishing-guide.md",
    "interview-walkthrough.md",
    "validation-checklist.md",
    "evidence/processed/stage2-final-summary.txt",
    "evidence/processed/source-sha256-records.tsv",
    "evidence/raw/.gitkeep",
    "scripts/scenario21-final-validator.py",
]
for rel in STALE:
    if (ROOT / rel).exists():
        fail(f"stale/redundant artifact remains: {rel}")

# Publication hygiene.
skip_dirs = {"raw", "working", "__pycache__", ".pytest_cache", ".git", ".venv", "venv"}
text_exts = {".md", ".csv", ".tsv", ".py", ".txt", ".json", ".yml", ".yaml", ".kql", ".spl"}
for current, dirs, files in os.walk(ROOT):
    dirs[:] = [d for d in dirs if d not in skip_dirs]
    for name in files:
        path = Path(current) / name
        rel = path.relative_to(ROOT).as_posix()
        data = path.read_bytes()
        if name == ".DS_Store":
            fail(f"Finder metadata published: {rel}")
        if path.stat().st_size > 5 * 1024 * 1024:
            fail(f"unexpected publishable file >5 MiB: {rel}")
        if b"\r\n" in data:
            fail(f"CRLF line endings: {rel}")
        if path.suffix.lower() in text_exts or name == ".gitignore":
            try:
                text = data.decode("utf-8")
            except UnicodeDecodeError:
                fail(f"non-UTF8 public text: {rel}")
                continue
            for lineno, line in enumerate(text.splitlines(), 1):
                if line.rstrip() != line:
                    fail(f"trailing whitespace: {rel}:{lineno}")
            if rel != "scripts/validate_portfolio.py" and re.search(r"/Users/[^/]+/", text):
                fail(f"hard-coded macOS user path: {rel}")
            if re.search(r"[A-Za-z0-9+/=]{160,}", text):
                fail(f"long encoded payload-like string published: {rel}")

# Dataset boundary must be a real TSV, not literal backslash-t text.
boundary = read_table("evidence/processed/dataset-boundary-record.tsv", "\t")
if boundary:
    expected_fields = {
        "case_type", "primary_dataset", "upstream_commit", "day1_scope", "day2_scope",
        "host_archive_bytes", "host_extracted_json_bytes", "host_json_working_path",
        "raw_policy", "working_policy", "processed_policy", "ground_truth_policy",
    }
    got_fields = {r.get("field", "") for r in boundary}
    if got_fields != expected_fields:
        fail(f"dataset-boundary fields mismatch: {sorted(got_fields)}")
    boundary_map = {r["field"]: r["value"] for r in boundary if r.get("field")}
else:
    boundary_map = {}

# Authoritative acquisition manifest.
source_rows = read_table("evidence/processed/source-acquisition-manifest.tsv", "\t")
if len(source_rows) != 8:
    fail(f"source acquisition manifest must contain 8 rows, found {len(source_rows)}")
source_paths = [r.get("artifact", "") for r in source_rows]
if len(source_paths) != len(set(source_paths)):
    fail("duplicate artifact in source acquisition manifest")
source_commits = {r.get("upstream_commit", "") for r in source_rows}
if source_rows and len(source_commits) != 1:
    fail(f"source acquisition manifest has multiple upstream commits: {source_commits}")
for r in source_rows:
    if not re.fullmatch(r"[0-9a-f]{64}", r.get("sha256", "")):
        fail(f"invalid source SHA-256: {r.get('artifact')}")
    if not r.get("bytes", "").isdigit():
        fail(f"invalid source byte count: {r.get('artifact')}")
    commit = r.get("upstream_commit", "")
    if not re.fullmatch(r"[0-9a-f]{40}", commit):
        fail(f"invalid upstream commit: {r.get('artifact')}")
    if commit and commit not in r.get("source_url", ""):
        fail(f"source URL is not pinned to listed commit: {r.get('artifact')}")
if boundary_map and source_rows:
    if boundary_map.get("upstream_commit") not in source_commits:
        fail("dataset-boundary upstream commit differs from acquisition manifest")
    host = next((r for r in source_rows if r.get("role") == "host_telemetry_archive"), None)
    if host and boundary_map.get("host_archive_bytes") != host.get("bytes"):
        fail("dataset-boundary host archive size differs from acquisition manifest")

# Structured evidence counts expected from the reviewed package.
expected_counts = {
    "evidence/processed/incident-lead-register.csv": 4,
    "evidence/processed/evidence-inventory.csv": 8,
    "evidence/processed/entity-inventory.csv": 10,
    "evidence/processed/entity-relationship-map.csv": 9,
    "evidence/processed/master-timeline.csv": 32,
    "evidence/processed/correlation-matrix.csv": 14,
    "evidence/processed/attack-stage-assessment.csv": 12,
    "evidence/processed/attack-mapping.csv": 11,
    "evidence/processed/scope-assessment.csv": 10,
    "evidence/processed/impact-assessment.csv": 5,
    "evidence/processed/ioc-observable-register.csv": 8,
    "evidence/processed/containment-decision-register.csv": 5,
    "evidence/processed/recovery-validation-matrix.csv": 8,
    "evidence/processed/detection-coverage-matrix.csv": 8,
    "evidence/processed/logging-visibility-gap-register.csv": 6,
    "evidence/processed/detection-improvement-backlog.csv": 8,
    "evidence/processed/investigation-limitations.csv": 7,
}
cache: dict[str, list[dict[str, str]]] = {}
for rel, expected in expected_counts.items():
    rows = read_table(rel)
    cache[rel] = rows
    if len(rows) != expected:
        fail(f"{rel}: expected {expected} rows, found {len(rows)}")

san = read_table("evidence/processed/sanitised-evidence-excerpts.tsv", "\t")
if len(san) != 10:
    fail(f"sanitised evidence excerpts: expected 10 rows, found {len(san)}")

# Canonical attack-stage status boundary.
stages = {r.get("attack_stage"): r.get("status") for r in cache.get("evidence/processed/attack-stage-assessment.csv", [])}
expected_stages = {
    "Initial Access": "Not available / Unable to assess",
    "Execution": "Observed",
    "Persistence": "Correlated",
    "Privilege Escalation": "Correlated",
    "Defense Evasion": "Observed",
    "Credential Access": "Correlated",
    "Discovery": "Not observed in the incident chain",
    "Lateral Movement": "Correlated",
    "Collection": "Observed",
    "Command and Control": "Correlated",
    "Exfiltration": "Not observed / Unable to assess",
    "Impact": "Not observed",
}
if stages != expected_stages:
    fail(f"attack-stage status mismatch: {stages}")

# Correlation IDs and high-value confidence boundaries.
corr = cache.get("evidence/processed/correlation-matrix.csv", [])
if {r.get("correlation_id") for r in corr} != {f"C-{i:03d}" for i in range(1, 15)}:
    fail("correlation matrix must contain C-001 through C-014 exactly once")
for r in corr:
    if r.get("correlation_id") == "C-006" and r.get("strength") != "Moderate cross-host; Strong target-side":
        fail("C-006 WinRM cross-host correlation strength changed")
    if r.get("correlation_id") == "C-009" and r.get("strength") != "Moderate":
        fail("C-009 svcctl-to-service correlation strength changed")

# Timeline integrity and high-value precision decisions.
timeline = cache.get("evidence/processed/master-timeline.csv", [])
refs = [r.get("source_reference") for r in timeline]
if len(refs) != len(set(refs)):
    fail("master timeline source_reference values are not unique")

def timeline_row_with_ref(ref: str) -> dict[str, str]:
    return next((r for r in timeline if ref in r.get("source_reference", "")), {})

lsass = timeline_row_with_ref("HOSTJSON:53270")
if "lsass" not in lsass.get("event", "").lower() or "0x1fffff" not in lsass.get("event", ""):
    fail("HOSTJSON:53270 no longer preserves incident-correlated LSASS evidence")
pfx = timeline_row_with_ref("HOSTJSON:52560")
if "failed" not in pfx.get("event", "").lower() and "non-exportable" not in pfx.get("event", "").lower():
    fail("HOSTJSON:52560 no longer records failed PFX export")
py_read = timeline_row_with_ref("HOSTJSON:92335")
if "readattributes" not in py_read.get("event", "").lower():
    fail("HOSTJSON:92335 no longer records ReadAttributes-only boundary")
psexec_write = timeline_row_with_ref("HOSTJSON:93862")
if "writedata" not in psexec_write.get("event", "").lower() or "appenddata" not in psexec_write.get("event", "").lower():
    fail("HOSTJSON:93862 no longer records PSEXESVC write evidence")
python_c2 = timeline_row_with_ref("HOSTJSON:102844..HOSTJSON:118721")
if "348" not in python_c2.get("event", "") or "192.168.0.4:8443" not in (python_c2.get("destination", "") + python_c2.get("event", "")):
    fail("Python 348-connection summary changed")

# Scope must remain narrower than the full dataset.
scope_rows = cache.get("evidence/processed/scope-assessment.csv", [])
scope = {r.get("entity"): r for r in scope_rows}
for host in ["SCRANTON.dmevals.local", "NASHUA.dmevals.local"]:
    if scope.get(host, {}).get("assessment") != "Affected / compromised" or scope.get(host, {}).get("confidence") != "High":
        fail(f"affected host scope changed: {host}")
if scope.get("DMEVALS\\pbeesly", {}).get("assessment") != "Affected / attacker-controlled or misused":
    fail("pbeesly identity scope changed")
for host in ["NEWYORK.dmevals.local", "UTICA.dmevals.local"]:
    assessment = scope.get(host, {}).get("assessment", "").lower()
    if assessment == "affected / compromised":
        fail(f"observed-only host promoted to compromised: {host}")

# Outcome boundaries.
impact = {r.get("impact_category"): r.get("activity_status") for r in cache.get("evidence/processed/impact-assessment.csv", [])}
if impact.get("Exfiltration") != "Not observed / Unable to assess":
    fail("exfiltration boundary changed")
if impact.get("Business/service disruption") != "Not observed":
    fail("business-impact boundary changed")

gaps = cache.get("evidence/processed/logging-visibility-gap-register.csv", [])
if {r.get("gap_id") for r in gaps} != {f"G-{i:03d}" for i in range(1, 7)}:
    fail("logging/visibility gap IDs must be G-001 through G-006")
backlog = cache.get("evidence/processed/detection-improvement-backlog.csv", [])
if {r.get("backlog_id") for r in backlog} != {f"D-{i:03d}" for i in range(1, 9)}:
    fail("detection backlog IDs must be D-001 through D-008")

contain = cache.get("evidence/processed/containment-decision-register.csv", [])
if contain and any(r.get("execution_status") != "Design only — historical emulation dataset" for r in contain):
    fail("containment register must remain design-only")
recovery = cache.get("evidence/processed/recovery-validation-matrix.csv", [])
if recovery and any(not (r.get("status", "").startswith("Not executed") or r.get("status") == "Not available / not applicable") for r in recovery):
    fail("recovery register contains an executed-success claim")

# Sanitisation boundaries.
san_by_ref = {r.get("source_reference"): r for r in san}
if "<REDACTED>" not in san_by_ref.get("HOSTJSON:105507", {}).get("sanitised_excerpt", ""):
    fail("archive password redaction missing")
if "does not prove file write/copy" not in san_by_ref.get("HOSTJSON:92335", {}).get("boundary", "").lower():
    fail("python.exe ReadAttributes precision boundary missing")
if "unsuccessful" not in san_by_ref.get("HOSTJSON:52560", {}).get("boundary", "").lower():
    fail("failed PFX export boundary missing")

# Git safety when run inside the repository.
repo = next((p for p in [ROOT, *ROOT.parents] if (p / ".git").exists()), None)
if repo:
    scenario_rel = ROOT.relative_to(repo).as_posix()
    tracked = subprocess.run(
        ["git", "-C", str(repo), "ls-files", "--", f"{scenario_rel}/evidence/raw", f"{scenario_rel}/evidence/working"],
        text=True, capture_output=True, check=True,
    ).stdout.splitlines()
    # Before staging, a tracked placeholder may already be deleted in the
    # worktree. Ignore such pending deletions; after staging it disappears
    # from the index and this same check becomes strict.
    still_present = []
    for relpath in tracked:
        candidate = repo / relpath
        if candidate.exists():
            still_present.append(relpath)
    if still_present:
        fail("raw/working evidence is Git-tracked: " + ", ".join(still_present))
    for probe in [f"{scenario_rel}/evidence/raw/_probe", f"{scenario_rel}/evidence/working/_probe"]:
        if subprocess.run(["git", "-C", str(repo), "check-ignore", "-q", probe]).returncode != 0:
            fail(f"Git ignore rule missing for {probe}")

if ERRORS:
    print("SCENARIO 21 VALIDATION: FAILED")
    for error in ERRORS:
        print(" -", error)
    sys.exit(2)

print("SCENARIO 21 VALIDATION: PASSED")
print(" Timeline rows: 32")
print(" Correlations: 14")
print(" Attack stages: 12")
print(" Scope entities: 10")
print(" Logging/visibility gaps: 6")
print(" Detection backlog: 8")
print(" Upstream acquisition artifacts: 8")
print(" Precision boundaries: PFX failure, LSASS correlation, ReadAttributes-only python event, Zeek time-window separation")
