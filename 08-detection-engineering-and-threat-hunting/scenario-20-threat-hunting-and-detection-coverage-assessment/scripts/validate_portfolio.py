#!/usr/bin/env python3
from __future__ import annotations

import csv
import hashlib
import os
import re
import subprocess
import sys
from collections import Counter
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
ERRORS=[]

def fail(msg):
    ERRORS.append(msg)

def read_csv(name, delimiter=","):
    path=ROOT/"evidence/processed"/name
    if not path.exists():
        fail(f"missing {path.relative_to(ROOT)}")
        return []
    with path.open(encoding="utf-8",newline="") as f:
        return list(csv.DictReader(f,delimiter=delimiter))

def key(r):
    # All three published coverage matrices use the stable pair
    # (hunt_id, behaviour). There is no behaviour_or_step column.
    return (r.get("hunt_id"),r.get("behaviour"))

findings=read_csv("hunt-findings.csv")
hyp=read_csv("hunt-hypothesis-matrix.csv")
attack=read_csv("attack-chain-coverage.csv")
detect=read_csv("detection-coverage-matrix.csv")
tele=read_csv("telemetry-coverage-matrix.csv")
dg=read_csv("detection-gap-register.csv")
lg=read_csv("logging-gap-register.csv")
opp=read_csv("detection-opportunity-register.csv")
neg=read_csv("negative-hunt-results.csv")
precision=read_csv("precision-validation-disposition.csv")
query_inventory=read_csv("hunt-query-inventory.csv")
prov=read_csv("source-sha256-records.tsv","\t")
results=read_csv("hunt-results.csv")

expected_hunts={"HC-01","HC-03","HC-05","HC-07","HC-08","HC-09","HC-10","HC-12"}
if {r.get("hunt_id") for r in findings} != expected_hunts:
    fail("hunt-findings hunt ID set mismatch")
if {r.get("hunt_id") for r in hyp} != expected_hunts:
    fail("hunt-hypothesis-matrix hunt ID set mismatch")

outcomes=Counter(r.get("outcome") for r in findings)
if outcomes != Counter({"Supported":5,"Negative hunt result":2,"Unable to assess":1}):
    fail(f"unexpected hunt outcomes: {dict(outcomes)}")

if {r["hunt_id"]:r["outcome"] for r in findings} != {r["hunt_id"]:r["outcome"] for r in hyp}:
    fail("hunt outcome mismatch between findings and hypothesis matrix")

for name,rows in [("attack",attack),("detection",detect),("telemetry",tele)]:
    if len(rows)!=32 or len({key(r) for r in rows})!=32:
        fail(f"{name} matrix must contain 32 unique behaviour/step rows")

if attack and detect and tele:
    A={key(r):r for r in attack}
    D={key(r):r for r in detect}
    T={key(r):r for r in tele}
    if set(A)!=set(D) or set(A)!=set(T):
        fail("coverage matrix key sets differ")
    else:
        for k in A:
            if not (A[k]["telemetry_status"]==D[k]["telemetry_status"]==T[k]["telemetry_status"]):
                fail(f"telemetry status mismatch for {k}")
            if A[k]["detection_status"]!=D[k]["detection_status"]:
                fail(f"detection status mismatch for {k}")

if len(dg)!=1 or dg[0].get("gap_id")!="DG-02" or dg[0].get("hunt_id")!="HC-03" or dg[0].get("gap_classification")!="Detection gap":
    fail("confirmed detection-gap register must contain only DG-02 / HC-03")
if len(lg)!=8:
    fail(f"expected 8 logging/visibility gaps, found {len(lg)}")
if len(opp)!=7:
    fail(f"expected 7 detection opportunities, found {len(opp)}")
if len(neg)!=2 or {r.get("hunt_id") for r in neg}!={"HC-07","HC-12"}:
    fail("negative hunt register must contain HC-07 and HC-12")
if len(precision)!=3:
    fail("precision-validation disposition must contain three corrections")
if len(query_inventory)!=8 or {r.get("hunt_id") for r in query_inventory}!=expected_hunts:
    fail("hunt-query inventory must contain eight hunts")
if len(results)!=34:
    fail(f"expected 34 hunt-result rows, found {len(results)}")

roles=Counter(r.get("artifact_role") for r in prov)
if roles != Counter({"hunt_input":39,"coverage_reference":8}):
    fail(f"unexpected provenance roles/counts: {dict(roles)}")

hunt_rows=[r for r in prov if r.get("artifact_role")=="hunt_input"]
coverage_rows=[r for r in prov if r.get("artifact_role")=="coverage_reference"]
git_true=[r for r in hunt_rows if r.get("git_reproducible")=="true"]
git_false=[r for r in hunt_rows if r.get("git_reproducible")=="false"]

if len(git_true)!=15 or len(git_false)!=24:
    fail(f"expected hunt-input provenance split 15 committed / 24 historical-only, found {len(git_true)} / {len(git_false)}")

for r in prov:
    if not re.fullmatch(r"[0-9a-f]{64}",r.get("sha256","")):
        fail(f"invalid provenance SHA-256: {r.get('relative_path')}")
    if not r.get("relative_path") or not r.get("size_bytes"):
        fail(f"incomplete provenance row: {r.get('relative_path')}")

for r in git_true:
    if not re.fullmatch(r"[0-9a-f]{40}",r.get("source_commit","")):
        fail(f"invalid committed source commit: {r.get('relative_path')}")
    if r.get("provenance_status")!="verified_committed_blob":
        fail(f"bad committed provenance status: {r.get('relative_path')}")

for r in git_false:
    if r.get("source_commit")!="not_available":
        fail(f"historical-only row must use source_commit=not_available: {r.get('relative_path')}")
    if r.get("provenance_status")!="historical_hash_only_no_reachable_git_blob":
        fail(f"bad historical-only provenance status: {r.get('relative_path')}")

for r in coverage_rows:
    if r.get("git_reproducible")!="true" or r.get("provenance_status")!="verified_coverage_reference":
        fail(f"bad coverage-reference provenance: {r.get('relative_path')}")
    if not re.fullmatch(r"[0-9a-f]{40}",r.get("source_commit","")):
        fail(f"invalid coverage-reference commit: {r.get('relative_path')}")

coverage_paths={r["relative_path"] for r in coverage_rows}
for r in query_inventory:
    refs=[x for x in r.get("existing_repository_query_references","").split(";") if x]
    for ref in refs:
        if ref not in coverage_paths:
            fail(f"unpinned material query reference: {ref}")

for r in precision:
    refs=[x for x in r.get("evidence","").split(";") if "/" in x]
    for ref in refs:
        if ref not in coverage_paths:
            fail(f"unpinned precision-review reference: {ref}")

stale=[
"PACKAGE-MANIFEST.tsv","package-validation.json","executive-summary.md",
"github-publishing-guide.md","interview-walkthrough.md","validation-checklist.md",
"negative-hunt-findings.md","attack-chain-coverage.md","telemetry-coverage-assessment.md",
"evidence/processed/hunt-source-access-log.csv","evidence/processed/sanitised-hunt-excerpts.tsv",
]
for rel in stale:
    if (ROOT/rel).exists():
        fail(f"stale/redundant publication artifact still present: {rel}")

skip={"raw","working","__pycache__",".pytest_cache",".venv","venv",".git"}
for current,dirs,files in os.walk(ROOT):
    dirs[:]=[d for d in dirs if d not in skip]
    for name in files:
        p=Path(current)/name
        data=p.read_bytes()
        rel=p.relative_to(ROOT).as_posix()
        if b"\r\n" in data:
            fail(f"CRLF found: {rel}")
        if name==".DS_Store":
            fail(f".DS_Store published: {rel}")
        if p.suffix.lower() in {".md",".csv",".tsv",".py",".json",".kql",".spl",".esql",".yml",".yaml",".txt"}:
            try:
                text=data.decode("utf-8")
            except UnicodeDecodeError:
                fail(f"non-UTF8 public text: {rel}")
                continue
            # Do not let the validator flag its own diagnostic regex as a
            # hard-coded local path. All other public text remains checked.
            if rel != "scripts/validate_portfolio.py" and re.search(r"/Users/[^/]+/",text):
                fail(f"hard-coded macOS user path: {rel}")

repo=None
for p in [ROOT,*ROOT.parents]:
    if (p/".git").exists():
        repo=p
        break

if repo:
    # Verify rows that explicitly claim Git reproducibility.
    for r in git_true + coverage_rows:
        spec=f"{r['source_commit']}:{r['relative_path']}"
        proc=subprocess.run(["git","-C",str(repo),"show",spec],capture_output=True)
        if proc.returncode!=0:
            fail(f"provenance source missing: {spec}")
            continue
        blob=proc.stdout
        if str(len(blob))!=r["size_bytes"]:
            fail(f"provenance size mismatch: {spec}")
        if hashlib.sha256(blob).hexdigest()!=r["sha256"]:
            fail(f"provenance hash mismatch: {spec}")

    # Verify that historical-only hashes still do not match any reachable
    # committed blob at the same path.
    commits=subprocess.run(
        ["git","-C",str(repo),"rev-list","--all","--topo-order"],
        capture_output=True,text=True,check=True
    ).stdout.splitlines()

    for r in git_false:
        for commit in commits:
            spec=f"{commit}:{r['relative_path']}"
            proc=subprocess.run(["git","-C",str(repo),"show",spec],capture_output=True)
            if proc.returncode!=0:
                continue
            if hashlib.sha256(proc.stdout).hexdigest()==r["sha256"]:
                fail(f"historical-only provenance now has a reachable Git match and should be updated: {spec}")
                break

    scenario_rel=ROOT.relative_to(repo).as_posix()
    tracked=subprocess.run(
        ["git","-C",str(repo),"ls-files","--",
         f"{scenario_rel}/evidence/raw",f"{scenario_rel}/evidence/working"],
        capture_output=True,text=True,check=True
    ).stdout.strip()
    if tracked:
        fail("raw/working evidence is tracked: "+tracked.replace("\n",", "))

    for probe in [
        f"{scenario_rel}/evidence/raw/_probe",
        f"{scenario_rel}/evidence/working/_probe",
    ]:
        if subprocess.run(["git","-C",str(repo),"check-ignore","-q",probe]).returncode!=0:
            fail(f"Git ignore rule missing for {probe}")

if ERRORS:
    print("SCENARIO 20 VALIDATION: FAILED")
    for e in ERRORS:
        print(" -",e)
    sys.exit(2)

print("SCENARIO 20 VALIDATION: PASSED")
print(" Hunts: 8 (5 supported, 2 negative, 1 unable to assess)")
print(" Coverage rows: 32")
print(" Confirmed detection gaps: 1 (DG-02 / HC-03)")
print(" Logging/visibility gaps: 8")
print(" Detection opportunities: 7")
print(" Provenance: 39 hunt inputs (15 Git-reproducible, 24 historical-hash-only) + 8 coverage references")
