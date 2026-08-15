#!/usr/bin/env python3
"""Fail closed on common secrets, raw payloads, and sensitive publishable artefacts."""
from __future__ import annotations

import argparse
import os
import re
from pathlib import Path

PATTERNS = {
    "private_key": re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
    "authorization_header": re.compile(r"(?i)authorization\s*:\s*(?:bearer|basic)\s+\S+"),
    "aws_access_key": re.compile(r"AKIA[0-9A-Z]{16}"),
    "generic_api_key": re.compile(r"(?i)(api[_-]?key|client[_-]?secret|access[_-]?token)\s*[:=]\s*[\"']?[A-Za-z0-9_\-]{16,}"),
    "cookie_header": re.compile(r"(?i)cookie\s*:\s*[^\n]{20,}"),
    "long_base64": re.compile(r"(?<![A-Za-z0-9+/])[A-Za-z0-9+/]{300,}={0,2}(?![A-Za-z0-9+/])"),
    "full_dns_payload": re.compile(r"(?i)3x6-\.\d+-\.(?:[A-Za-z0-9*_-]{20,}-\.){3,}"),
}
FORBIDDEN = {
    ".pcap", ".pcapng", ".evtx", ".sqlite", ".sqlite3", ".db",
    ".har", ".dmp", ".dump", ".zip", ".7z", ".rar", ".tar", ".gz", ".tgz",
    ".xlsx", ".xls", ".docx", ".doc", ".pptx", ".ppt",
}
LOCAL_EVIDENCE_DIRS = (Path("evidence/raw"), Path("evidence/working"))
RUNTIME_DIR_NAMES = {"__pycache__", ".venv", "venv", ".pytest_cache"}


def is_local_evidence(relative_path: Path) -> bool:
    return any(relative_path == base or base in relative_path.parents for base in LOCAL_EVIDENCE_DIRS)


def iter_publishable_files(root: Path):
    for current, dirnames, filenames in os.walk(root):
        current_path = Path(current)
        rel_current = current_path.relative_to(root)
        kept = []
        for dirname in dirnames:
            child_rel = rel_current / dirname
            if is_local_evidence(child_rel) or dirname in RUNTIME_DIR_NAMES:
                continue
            kept.append(dirname)
        dirnames[:] = kept
        for filename in filenames:
            yield current_path / filename


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--scenario", required=True)
    args = parser.parse_args()
    root = Path(args.scenario).expanduser().resolve()
    errors: list[str] = []

    for path in iter_publishable_files(root):
        relative = path.relative_to(root)
        if path.suffix.lower() in FORBIDDEN:
            errors.append(f"forbidden publishable extension: {relative}")
        if path.stat().st_size > 10_000_000:
            errors.append(f"oversized publishable file: {relative} ({path.stat().st_size})")
        text = path.read_text(encoding="utf-8", errors="ignore")
        for name, pattern in PATTERNS.items():
            if pattern.search(text):
                errors.append(f"{name}: {relative}")

    if errors:
        print("\n".join(errors))
        return 1
    print("OK: sanitisation tests passed for publishable content")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
