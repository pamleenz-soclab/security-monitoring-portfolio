#!/usr/bin/env python3
import os
import re
import sys
from pathlib import Path

root = Path(__file__).resolve().parents[2]
patterns = [
    ("private_key", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----")),
    ("jwt", re.compile(r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}")),
    ("authorization", re.compile(r"(?i)authorization:\s*bearer\s+\S+")),
    ("aws_key", re.compile(r"AKIA[0-9A-Z]{16}")),
]
skip_dirs = {"raw", "working", "__pycache__", ".venv", "venv", ".pytest_cache", ".git"}
bad = []
for current, dirs, files in os.walk(root):
    dirs[:] = [d for d in dirs if d not in skip_dirs]
    for name in files:
        p = Path(current) / name
        if p.suffix.lower() in (".png", ".jpg", ".jpeg", ".zip"):
            continue
        try:
            text = p.read_text(encoding="utf-8")
        except (UnicodeDecodeError, OSError):
            continue
        for label, rx in patterns:
            if rx.search(text):
                bad.append(f"{label}: {p.relative_to(root)}")
if bad:
    print("\n".join(bad))
    sys.exit(2)
print("Sanitisation tests: PASSED")
