#!/usr/bin/env python3
"""Generate a stable manifest for publishable Scenario 17 files."""
from __future__ import annotations

import argparse
import csv
import hashlib
from pathlib import Path

EXCLUDED_PREFIXES = ("evidence/raw/", "evidence/working/")
EXCLUDED_NAMES = {"PACKAGE-MANIFEST.tsv"}


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--scenario-dir", required=True, type=Path)
    args = parser.parse_args()
    root = args.scenario_dir.expanduser().resolve()
    output = root / "PACKAGE-MANIFEST.tsv"

    rows = []
    for path in sorted(root.rglob("*")):
        if not path.is_file():
            continue
        rel = path.relative_to(root).as_posix()
        if rel in EXCLUDED_NAMES or rel.startswith(EXCLUDED_PREFIXES):
            continue
        rows.append({
            "path": rel,
            "size_bytes": str(path.stat().st_size),
            "sha256": sha256(path),
        })

    with output.open("w", encoding="utf-8", newline="") as fh:
        writer = csv.DictWriter(
            fh, fieldnames=["path", "size_bytes", "sha256"], delimiter="\t"
        )
        writer.writeheader()
        writer.writerows(rows)

    print(f"Wrote {len(rows)} manifest entries to {output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
