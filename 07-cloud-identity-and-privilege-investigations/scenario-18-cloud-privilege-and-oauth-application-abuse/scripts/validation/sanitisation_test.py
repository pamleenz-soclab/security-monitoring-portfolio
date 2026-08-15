#!/usr/bin/env python3
"""Scan Scenario 18 publishable content for accidental real identity or secret material."""
from __future__ import annotations

import argparse
import json
import os
import re
from pathlib import Path

TEXT_SUFFIXES = {".md", ".txt", ".csv", ".tsv", ".json", ".jsonl", ".yml", ".yaml", ".py", ".sh", ".sql", ".kql", ".spl", ".esql"}
LOCAL_PREFIXES = ("evidence/raw", "evidence/working")
RUNTIME_DIRS = {"__pycache__", ".pytest_cache", ".venv", "venv"}
UUID_RE = re.compile(r"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}\b")
EMAIL_RE = re.compile(r"\b[A-Za-z0-9._%+-]+@([A-Za-z0-9.-]+\.[A-Za-z]{2,})\b")
USER_PATH = re.compile(r"(?:/Users/[^/\s]+|[A-Za-z]:\\\\Users\\\\[^\\\\\s]+)")
SECRET_PATTERNS = {
    "private_key": re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
    "jwt_like_token": re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b"),
    "authorization_header": re.compile(r"(?i)\bAuthorization\s*:\s*(?:Bearer|Basic)\s+\S+"),
    "client_secret_assignment": re.compile(r"(?i)\bclient[_ -]?secret\s*[:=]\s*['\"][^'\"]+"),
}
ALLOWED_EMAIL_DOMAINS = {"synthetic.example", "example.com"}


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
    ap.add_argument("--report", type=Path)
    ap.add_argument("--allow-synthetic-uuids", action="store_true")
    args = ap.parse_args()
    root = args.scenario_dir.expanduser().resolve()
    findings: list[dict[str, str]] = []
    checked = 0

    for path in publishable_files(root):
        rel = path.relative_to(root).as_posix()
        if path.suffix.lower() not in TEXT_SUFFIXES:
            continue
        checked += 1
        text = path.read_text(encoding="utf-8", errors="strict")

        # Do not flag literal forbidden-pattern strings inside validation helpers themselves.
        secret_pattern_helpers = {
            "scripts/validation/sanitisation_test.py",
            "scripts/validation/validate_synthetic_package.py",
        }
        if rel not in secret_pattern_helpers:
            for label, pattern in SECRET_PATTERNS.items():
                if pattern.search(text):
                    findings.append({"file": rel, "type": label, "value": "matched"})

        for match in EMAIL_RE.finditer(text):
            domain = match.group(1).lower()
            if domain not in ALLOWED_EMAIL_DOMAINS:
                findings.append({"file": rel, "type": "non_synthetic_email_domain", "value": domain})

        if rel not in {"scripts/validation/portfolio_validator.py", "scripts/validation/sanitisation_test.py"} and USER_PATH.search(text):
            findings.append({"file": rel, "type": "hard_coded_local_user_path", "value": "matched"})

        if not args.allow_synthetic_uuids and UUID_RE.search(text):
            findings.append({"file": rel, "type": "uuid_requires_review", "value": "synthetic IDs expected in this scenario"})

    result = {
        "status": "PASS" if not findings else "FAIL",
        "checked_files": checked,
        "findings": findings,
    }
    if args.report:
        report = args.report.expanduser().resolve()
        report.parent.mkdir(parents=True, exist_ok=True)
        report.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps({"status": result["status"], "checked_files": checked, "findings": len(findings)}, indent=2))
    if findings:
        for finding in findings:
            print(" -", finding)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
