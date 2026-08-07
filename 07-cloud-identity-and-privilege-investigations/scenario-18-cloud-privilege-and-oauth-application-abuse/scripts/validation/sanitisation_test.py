#!/usr/bin/env python3
"""Scan publishable outputs for secrets and non-synthetic identity material."""

from __future__ import annotations

import argparse
import json
import re
from pathlib import Path

UUID_RE = re.compile(r"\b[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}\b", re.I)
UPN_RE = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
FORBIDDEN = ["Bearer ", "Authorization:", "-----BEGIN PRIVATE KEY-----", "-----BEGIN CERTIFICATE-----", "refresh_token", "access_token", "client_secret"]

def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", required=True, type=Path)
    parser.add_argument("--report", required=True, type=Path)
    parser.add_argument("--allow-synthetic-uuids", action="store_true")
    args = parser.parse_args()

    base = args.input.resolve()
    findings = []
    for path in base.rglob("*"):
        if not path.is_file():
            continue
        try:
            text = path.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            findings.append({"file": str(path), "type": "binary_file", "value": "Review manually"})
            continue
        for marker in FORBIDDEN:
            if marker.lower() in text.lower():
                findings.append({"file": str(path), "type": "forbidden_marker", "value": marker})
        for upn in sorted(set(UPN_RE.findall(text))):
            if not upn.endswith("@synthetic.example"):
                findings.append({"file": str(path), "type": "non_synthetic_upn", "value": upn})
        if not args.allow_synthetic_uuids:
            for value in sorted(set(UUID_RE.findall(text))):
                findings.append({"file": str(path), "type": "uuid_requires_aliasing", "value": value})

    result = {"status": "PASS" if not findings else "REVIEW", "input": str(base), "findings": findings}
    args.report.parent.mkdir(parents=True, exist_ok=True)
    args.report.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps({"status": result["status"], "findings": len(findings), "report": str(args.report)}, indent=2))
    return 0 if not findings else 2

if __name__ == "__main__":
    raise SystemExit(main())
