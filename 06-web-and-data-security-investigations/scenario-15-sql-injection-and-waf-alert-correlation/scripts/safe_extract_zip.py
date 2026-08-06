#!/usr/bin/env python3
"""Safely extract a ZIP archive after blocking absolute paths, traversal, and symlinks."""
from __future__ import annotations

import argparse
import os
import stat
import sys
import zipfile
from pathlib import Path


def safe_member(name: str) -> bool:
    p = Path(name)
    return bool(name) and not p.is_absolute() and ".." not in p.parts and not name.startswith(("/", "\\"))


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("archive", type=Path)
    ap.add_argument("destination", type=Path)
    args = ap.parse_args()

    if not args.archive.is_file():
        print(f"ERROR: archive not found: {args.archive}", file=sys.stderr)
        return 2

    args.destination.mkdir(parents=True, exist_ok=True)
    root = args.destination.resolve()

    with zipfile.ZipFile(args.archive) as zf:
        bad: list[str] = []
        for info in zf.infolist():
            mode = (info.external_attr >> 16) & 0xFFFF
            target = (args.destination / info.filename).resolve()
            if not safe_member(info.filename):
                bad.append(f"unsafe path: {info.filename}")
            elif os.path.commonpath([str(root), str(target)]) != str(root):
                bad.append(f"path escapes destination: {info.filename}")
            elif stat.S_ISLNK(mode):
                bad.append(f"symlink entry: {info.filename}")
        if bad:
            print("ERROR: unsafe ZIP entries detected:", file=sys.stderr)
            for item in bad[:50]:
                print(f"  {item}", file=sys.stderr)
            return 3
        zf.extractall(args.destination)
        print(f"Extracted {len(zf.infolist())} entries to {args.destination}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
