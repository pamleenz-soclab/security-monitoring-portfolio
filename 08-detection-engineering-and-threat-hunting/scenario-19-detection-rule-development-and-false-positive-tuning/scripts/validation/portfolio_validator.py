#!/usr/bin/env python3

import csv
import json
import sys
from pathlib import Path

import yaml


root = Path(__file__).resolve().parents[2]
errors = []

required = [
    "README.md",
    "scenario-scope.md",
    "detection-engineering.md",
    "evidence/processed/fixture-ground-truth.csv",
    "tests/results/final-v3-test-results.csv",
    "PACKAGE-MANIFEST.tsv",
]

for rel in required:
    if not (root / rel).exists():
        errors.append("missing " + rel)


# Local-only paths are intentionally excluded from public-content validation.
# Their Git-ignore / tracking status is validated separately by
# git_aware_validator.py.
LOCAL_ONLY_PREFIXES = (
    ".venv/",
    "venv/",
    "evidence/raw/",
    "evidence/working/",
)


def is_local_only(rel: str) -> bool:
    return any(rel.startswith(prefix) for prefix in LOCAL_ONLY_PREFIXES)


for path in root.rglob("*"):
    if not path.is_file():
        continue

    rel = path.relative_to(root).as_posix()

    if is_local_only(rel):
        continue

    # Forbidden public artefacts and size.
    if path.suffix.lower() in (
        ".pcap",
        ".pcapng",
        ".evtx",
        ".sqlite",
        ".sqlite3",
        ".db",
        ".zip",
    ):
        errors.append("forbidden file " + rel)

    if path.stat().st_size > 5 * 1024 * 1024:
        errors.append("large file " + rel)

    if "__pycache__" in rel:
        errors.append("cache " + rel)

    # Validate structured public files.
    if path.suffix.lower() in (".yml", ".yaml"):
        try:
            yaml.safe_load(path.read_text(encoding="utf-8"))
        except Exception as exc:
            errors.append(f"invalid yaml {rel}: {exc}")

    if path.suffix.lower() == ".json":
        try:
            json.loads(path.read_text(encoding="utf-8"))
        except Exception as exc:
            errors.append(f"invalid json {rel}: {exc}")

    if path.suffix.lower() in (".csv", ".tsv"):
        try:
            delimiter = "\t" if path.suffix.lower() == ".tsv" else ","
            with path.open(newline="", encoding="utf-8") as handle:
                list(csv.reader(handle, delimiter=delimiter))
        except Exception as exc:
            errors.append(f"invalid table {rel}: {exc}")

    # Public text files must not contain trailing whitespace.
    if path.suffix.lower() in (
        ".md",
        ".py",
        ".yml",
        ".yaml",
        ".json",
        ".csv",
        ".tsv",
        ".kql",
        ".spl",
        ".esql",
        ".sh",
    ):
        try:
            for line_number, line in enumerate(
                path.read_text(encoding="utf-8").splitlines(), 1
            ):
                if line.rstrip() != line:
                    errors.append(
                        f"trailing whitespace {rel}:{line_number}"
                    )
        except UnicodeDecodeError:
            errors.append("unable to decode public text file " + rel)


# Validate rule IDs and versions.
rule_ids = []

for path in (root / "detections/specifications").glob("*.yml"):
    data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}

    rule_id = data.get("rule_id")
    rule_ids.append(rule_id)

    if not data.get("version"):
        errors.append("missing version " + path.name)

if len(rule_ids) != len(set(rule_ids)):
    errors.append("duplicate rule IDs in specifications")


# Every public fixture requires explicit provenance and expected outcome.
for path in (root / "tests/fixtures").glob("*/*.jsonl"):
    for line_number, line in enumerate(
        path.read_text(encoding="utf-8").splitlines(), 1
    ):
        if not line.strip():
            continue

        record = json.loads(line)

        for key in (
            "source_scenario",
            "synthetic_or_sanitised",
            "expected_result",
            "expected_classification",
        ):
            if not record.get(key):
                errors.append(
                    f"{path.relative_to(root)}:{line_number} missing {key}"
                )


if errors:
    print("PORTFOLIO VALIDATION: FAILED")
    print("\n".join(errors))
    sys.exit(2)

print("PORTFOLIO VALIDATION: PASSED")
