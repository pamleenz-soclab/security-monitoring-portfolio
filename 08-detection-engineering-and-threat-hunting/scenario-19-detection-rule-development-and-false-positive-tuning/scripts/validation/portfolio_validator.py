#!/usr/bin/env python3
import csv
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path

try:
    import yaml as _pyyaml
except ModuleNotFoundError:
    _pyyaml = None

root = Path(__file__).resolve().parents[2]
errors = []

def _ruby_yaml_to_json(path: Path):
    ruby = shutil.which("ruby")
    if not ruby:
        return None
    code = (
        'require "yaml"; require "json"; '
        'obj = YAML.load_file(ARGV[0]); '
        'STDOUT.write(JSON.generate(obj))'
    )
    proc = subprocess.run(
        [ruby, "-e", code, str(path)],
        capture_output=True,
        text=True,
    )
    if proc.returncode != 0:
        raise ValueError(proc.stderr.strip() or "Ruby YAML parser failed")
    return json.loads(proc.stdout) if proc.stdout.strip() else None

def load_yaml_if_possible(path: Path):
    """Load YAML with PyYAML when present, otherwise Ruby Psych when present."""
    text = path.read_text(encoding="utf-8")
    if _pyyaml is not None:
        return _pyyaml.safe_load(text), "PyYAML"
    ruby_data = _ruby_yaml_to_json(path)
    if ruby_data is not None:
        return ruby_data, "Ruby Psych"
    return None, "structural fallback"

def validate_yaml(path: Path):
    """
    Validate YAML without making PyYAML a hard dependency.
    Falls back to Ruby Psych on macOS, then conservative structural checks.
    """
    data, parser = load_yaml_if_possible(path)
    if parser != "structural fallback":
        return data, parser

    text = path.read_text(encoding="utf-8")
    if not text.strip():
        raise ValueError("empty YAML file")
    if "\t" in text:
        raise ValueError("tab character found")
    if path.parent.name == "specifications":
        for marker in ("rule_id:", "version:", "logic:"):
            if marker not in text:
                raise ValueError(f"missing required marker {marker}")
    elif path.parent.name == "sigma":
        for marker in ("title:", "detection:"):
            if marker not in text:
                raise ValueError(f"missing Sigma marker {marker}")
    return None, parser

def top_level_scalar(path: Path, key: str):
    """
    Read a simple top-level scalar if a full YAML parser is unavailable.
    Scenario 19 specifications store rule_id/version as top-level scalars.
    """
    pattern = re.compile(rf"^{re.escape(key)}:\s*(.*?)\s*$")
    for line in path.read_text(encoding="utf-8").splitlines():
        if line.startswith((" ", "\t", "#")):
            continue
        m = pattern.match(line)
        if m:
            value = m.group(1).strip()
            if (
                len(value) >= 2
                and value[0] == value[-1]
                and value[0] in ("'", '"')
            ):
                value = value[1:-1]
            return value
    return None

required = [
    "README.md",
    "scenario-scope.md",
    "detection-engineering.md",
    "evidence/processed/fixture-ground-truth.csv",
    "tests/expected/expected-results.csv",
    "tests/results/final-v3-test-results.csv",
    "evidence/processed/source-sha256-records.tsv",
]
for rel in required:
    if not (root / rel).exists():
        errors.append("missing " + rel)

skip_dirs = {"raw", "working", "__pycache__", ".venv", "venv", ".pytest_cache", ".git"}
yaml_parser_modes = set()

for current, dirs, files in os.walk(root):
    dirs[:] = [d for d in dirs if d not in skip_dirs]
    for name in files:
        path = Path(current) / name
        rel = path.relative_to(root).as_posix()

        if path.suffix.lower() in (".pcap", ".pcapng", ".evtx", ".sqlite", ".sqlite3", ".db", ".zip"):
            errors.append("forbidden file " + rel)

        if path.stat().st_size > 5 * 1024 * 1024:
            errors.append("large file " + rel)

        if path.suffix.lower() in (".yml", ".yaml"):
            try:
                _, parser = validate_yaml(path)
                yaml_parser_modes.add(parser)
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

        if path.suffix.lower() in (
            ".md", ".py", ".yml", ".yaml", ".json", ".csv", ".tsv",
            ".kql", ".spl", ".esql", ".sh"
        ):
            try:
                for line_number, line in enumerate(
                    path.read_text(encoding="utf-8").splitlines(), 1
                ):
                    if line.rstrip() != line:
                        errors.append(f"trailing whitespace {rel}:{line_number}")
            except UnicodeDecodeError:
                errors.append("unable to decode public text file " + rel)

rule_ids = []
for path in (root / "detections/specifications").glob("*.yml"):
    try:
        data, parser = load_yaml_if_possible(path)
        yaml_parser_modes.add(parser)
    except Exception as exc:
        errors.append(f"invalid specification yaml {path.name}: {exc}")
        data, parser = None, "failed"

    if isinstance(data, dict):
        rule_id = data.get("rule_id")
        version = data.get("version")
    else:
        rule_id = top_level_scalar(path, "rule_id")
        version = top_level_scalar(path, "version")

    rule_ids.append(rule_id)
    if not version:
        errors.append("missing version " + path.name)

if len(rule_ids) != len(set(rule_ids)):
    errors.append("duplicate rule IDs in specifications")
if set(rule_ids) != {f"R19-{i:02d}" for i in range(1, 7)}:
    errors.append("unexpected final specification rule ID set")

# External oracle, fixtures and human-readable ground truth must be one-to-one and consistent.
def load_csv(rel):
    return list(csv.DictReader((root / rel).open(encoding="utf-8", newline="")))

expected_rows = load_csv("tests/expected/expected-results.csv")
ground_rows = load_csv("evidence/processed/fixture-ground-truth.csv")
expected = {r["fixture_id"]: r for r in expected_rows}
ground = {r["fixture_id"]: r for r in ground_rows}
fixtures = {}

for path in (root / "tests/fixtures").glob("*/*.jsonl"):
    for line_number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        if not line.strip():
            continue
        record = json.loads(line)
        fid = record.get("fixture_id")
        if not fid:
            errors.append(f"{path.relative_to(root)}:{line_number} missing fixture_id")
            continue
        if fid in fixtures:
            errors.append("duplicate fixture_id " + fid)
        fixtures[fid] = record

if set(fixtures) != set(expected) or set(fixtures) != set(ground):
    errors.append("fixture/oracle/ground-truth fixture ID sets differ")

for fid, f in fixtures.items():
    e = expected.get(fid, {})
    g = ground.get(fid, {})
    for key in ("rule_id", "expected_result", "expected_classification"):
        if str(f.get(key, "")) != str(e.get(key, "")):
            errors.append(f"{fid} fixture/oracle mismatch {key}")
        if str(f.get(key, "")) != str(g.get(key, "")):
            errors.append(f"{fid} fixture/ground mismatch {key}")
    if str(f.get("ground_truth_label", "")) != str(g.get("ground_truth_label", "")):
        errors.append(f"{fid} fixture/ground mismatch ground_truth_label")

# Verify source-provenance hashes when the full Git repository is available.
repo = next((p for p in [root, *root.parents] if (p / ".git").exists()), None)
prov_path = root / "evidence/processed/source-sha256-records.tsv"

if prov_path.exists():
    prov = list(
        csv.DictReader(
            prov_path.open(encoding="utf-8", newline=""),
            delimiter="\t",
        )
    )
    for r in prov:
        if len(r.get("sha256", "")) != 64 or not r.get("source_commit") or not r.get("source_path"):
            errors.append("invalid source provenance row")
            continue
        if repo:
            spec = f"{r['source_commit']}:{r['source_path']}"
            check = subprocess.run(
                ["git", "-C", str(repo), "cat-file", "-e", spec],
                capture_output=True,
            )
            if check.returncode != 0:
                errors.append("source provenance path missing at commit: " + spec)
                continue
            blob = subprocess.run(
                ["git", "-C", str(repo), "show", spec],
                capture_output=True,
                check=True,
            ).stdout
            if hashlib.sha256(blob).hexdigest() != r["sha256"]:
                errors.append("source provenance hash mismatch: " + spec)

if errors:
    print("PORTFOLIO VALIDATION: FAILED")
    print("\n".join(errors))
    sys.exit(2)

mode = ", ".join(sorted(yaml_parser_modes)) if yaml_parser_modes else "none"
print(f"PORTFOLIO VALIDATION: PASSED (YAML validation: {mode})")
