#!/usr/bin/env python3
import argparse
import csv
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from local_rule_evaluator import evaluate


def load_cases(root):
    out = []
    for p in sorted((root / "tests/fixtures").glob("*/*.jsonl")):
        for line in p.read_text(encoding="utf-8").splitlines():
            if line.strip():
                out.append(json.loads(line))
    return out


def load_expected(root):
    rows = list(csv.DictReader((root / "tests/expected/expected-results.csv").open(encoding="utf-8", newline="")))
    mapping = {r["fixture_id"]: r for r in rows}
    if len(rows) != len(mapping):
        raise SystemExit("duplicate fixture_id in expected-results.csv")
    return mapping


def classification(expected_result, expected_classification, actual):
    if actual == "Unable to evaluate":
        return "Unable to test"
    if actual == "Match":
        if expected_result == "No match":
            return "False Positive"
        if expected_classification == "Benign Positive":
            return "Benign Positive"
        return "True Positive"
    if actual == "No match":
        if expected_result == "Match":
            return "False Negative"
        return "True Negative"
    raise ValueError(actual)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--root", default=str(Path(__file__).resolve().parents[2]))
    ap.add_argument("--output", default="")
    a = ap.parse_args()
    root = Path(a.root)
    cases = load_cases(root)
    expected = load_expected(root)
    case_ids = {c["fixture_id"] for c in cases}
    if case_ids != set(expected):
        raise SystemExit("fixture IDs and external expected-result IDs differ; run provenance validation")

    rows = []
    for c in cases:
        e = expected[c["fixture_id"]]
        actual = evaluate(c)
        rows.append({
            "fixture_id": c["fixture_id"],
            "rule_id": c["rule_id"],
            "expected_result": e["expected_result"],
            "actual_result": actual,
            "expected_classification": e["expected_classification"],
            "actual_classification": classification(e["expected_result"], e["expected_classification"], actual),
            "pass": str(actual == e["expected_result"]).upper(),
            "source_scenario": c["source_scenario"],
            "synthetic_or_sanitised": c["synthetic_or_sanitised"],
            "notes": c.get("notes", ""),
        })

    out = Path(a.output) if a.output else root / "tests/results/final-v3-test-results.csv"
    out.parent.mkdir(parents=True, exist_ok=True)
    with out.open("w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=rows[0].keys(), lineterminator="\n")
        w.writeheader()
        w.writerows(rows)

    passed = sum(r["pass"] == "TRUE" for r in rows)
    print(f"V3 regression: {passed}/{len(rows)} passed")
    print(f"External oracle: {root / 'tests/expected/expected-results.csv'}")
    print(f"Output: {out}")
    if passed != len(rows):
        sys.exit(2)


if __name__ == "__main__":
    main()
