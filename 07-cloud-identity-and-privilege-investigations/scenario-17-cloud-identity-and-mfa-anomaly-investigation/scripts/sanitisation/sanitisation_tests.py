#!/usr/bin/env python3
"""Scan publishable Scenario 17 content for unsafe identity or secret material."""
from __future__ import annotations

import argparse
import os
import re
from pathlib import Path

TEXT_SUFFIXES = {".md", ".txt", ".csv", ".tsv", ".json", ".jsonl", ".yml", ".yaml", ".py", ".sh", ".sql", ".kql", ".spl", ".esql"}
LOCAL_PREFIXES = ("evidence/raw", "evidence/working")
RUNTIME_DIRS = {"__pycache__", ".pytest_cache", ".venv", "venv"}
UUID = re.compile(r"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}\b")
EMAIL = re.compile(r"\b[A-Za-z0-9._%+-]+@([A-Za-z0-9.-]+\.[A-Za-z]{2,})\b")
SECRET_PATTERNS = {
    "Authorization header": re.compile(r"(?i)\bAuthorization\s*:\s*(?:Bearer|Basic)\s+\S+"),
    "JWT-like token": re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b"),
    "Private key": re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
    "MFA seed": re.compile(r"(?i)\botpauth://|mfa[_ -]?seed\s*[:=]"),
    "Client secret assignment": re.compile(r"(?i)\bclient[_ -]?secret\s*[:=]\s*['\"][^'\"]+"),
}
ALLOWED_EMAIL_DOMAINS = {"example.invalid"}
ALLOWED_UUID_FILES = {
    "scripts/acquisition/scenario17_generate_synthetic_dataset.py",
    "scripts/parsing/scenario17_first_pass.py",
    "scripts/analysis/scenario17_precise_verification.py",
    "scripts/analysis/build_processed_evidence.py",
    "queries/correlation/local-sqlite-verification.sql",
    "detections/generic/mfa-fatigue-rule.yml",
}
ARCHIVE_SUFFIXES = {".zip", ".7z", ".rar", ".gz", ".tgz"}


def is_local(rel: Path) -> bool:
    posix = rel.as_posix()
    return any(posix == p or posix.startswith(p + "/") for p in LOCAL_PREFIXES)


def publishable_files(root: Path):
    for current, dirs, files in os.walk(root):
        current_path = Path(current)
        rel_current = current_path.relative_to(root)
        kept = []
        for d in dirs:
            child = rel_current / d
            if d in RUNTIME_DIRS or is_local(child):
                continue
            kept.append(d)
        dirs[:] = kept
        for name in files:
            yield current_path / name


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--scenario-dir", required=True, type=Path)
    args = ap.parse_args()
    root = args.scenario_dir.expanduser().resolve()
    failures: list[str] = []
    checked = 0

    for path in publishable_files(root):
        rel = path.relative_to(root).as_posix()
        if path.suffix.lower() in ARCHIVE_SUFFIXES:
            failures.append(f"{rel}: archive must not be published inside scenario")
        if path.suffix.lower() not in TEXT_SUFFIXES:
            continue
        checked += 1
        text = path.read_text(encoding="utf-8", errors="replace")
        for label, pattern in SECRET_PATTERNS.items():
            if pattern.search(text): failures.append(f"{rel}: {label}")
        for match in EMAIL.finditer(text):
            domain = match.group(1).lower()
            if domain not in ALLOWED_EMAIL_DOMAINS and not domain.endswith(".example.invalid"):
                failures.append(f"{rel}: non-example email domain {domain}")
        if rel.startswith("evidence/processed/") and UUID.search(text):
            failures.append(f"{rel}: raw UUID present in processed evidence")
        elif UUID.search(text) and rel not in ALLOWED_UUID_FILES:
            failures.append(f"{rel}: UUID requires review")

    if failures:
        print("SANITISATION: FAIL")
        for item in sorted(set(failures)): print(f"  {item}")
        return 1
    print(f"SANITISATION: PASS ({checked} publishable text files checked)")
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
