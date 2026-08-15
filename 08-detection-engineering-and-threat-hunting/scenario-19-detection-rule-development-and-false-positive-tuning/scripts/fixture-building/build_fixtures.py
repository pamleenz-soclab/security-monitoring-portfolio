#!/usr/bin/env python3
"""Validate fixture provenance and keep fixture labels aligned with an external oracle."""
import csv
import json
import sys
from pathlib import Path

root = Path(__file__).resolve().parents[2]
expected_path = root / "tests/expected/expected-results.csv"
ground_path = root / "evidence/processed/fixture-ground-truth.csv"

expected_rows = list(csv.DictReader(expected_path.open(encoding="utf-8", newline="")))
ground_rows = list(csv.DictReader(ground_path.open(encoding="utf-8", newline="")))
expected = {r["fixture_id"]: r for r in expected_rows}
ground = {r["fixture_id"]: r for r in ground_rows}

bad = []
fixtures = {}
for p in sorted((root / "tests/fixtures").glob("*/*.jsonl")):
    for n, line in enumerate(p.read_text(encoding="utf-8").splitlines(), 1):
        if not line.strip():
            continue
        x = json.loads(line)
        fid = x.get("fixture_id")
        if not fid:
            bad.append(f"{p}:{n}: missing fixture_id")
            continue
        if fid in fixtures:
            bad.append(f"duplicate fixture_id: {fid}")
        fixtures[fid] = x
        for k in (
            "rule_id", "source_scenario", "source_file", "synthetic_or_sanitised",
            "expected_result", "expected_classification", "ground_truth_label", "telemetry_label",
        ):
            if x.get(k) in ("", None):
                bad.append(f"{p}:{n}: missing {k}")

if len(expected_rows) != len(expected):
    bad.append("duplicate fixture_id in tests/expected/expected-results.csv")
if len(ground_rows) != len(ground):
    bad.append("duplicate fixture_id in fixture-ground-truth.csv")

for label, mapping in (("oracle", expected), ("ground truth", ground)):
    missing = sorted(set(fixtures) - set(mapping))
    extra = sorted(set(mapping) - set(fixtures))
    if missing:
        bad.append(f"{label} missing fixture IDs: {', '.join(missing)}")
    if extra:
        bad.append(f"{label} has unknown fixture IDs: {', '.join(extra)}")

for fid, x in fixtures.items():
    e = expected.get(fid)
    g = ground.get(fid)
    if e:
        for key in ("rule_id", "expected_result", "expected_classification"):
            if str(x.get(key, "")) != str(e.get(key, "")):
                bad.append(f"{fid}: fixture/oracle mismatch for {key}")
    if g:
        for key in ("rule_id", "expected_result", "expected_classification", "ground_truth_label"):
            if str(x.get(key, "")) != str(g.get(key, "")):
                bad.append(f"{fid}: fixture/ground-truth mismatch for {key}")

print(f"Fixture records checked: {len(fixtures)}")
if bad:
    print("\n".join(bad))
    sys.exit(2)
print("Fixture/oracle/ground-truth consistency: PASSED")
