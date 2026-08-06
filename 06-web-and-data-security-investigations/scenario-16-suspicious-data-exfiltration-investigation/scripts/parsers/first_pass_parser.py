#!/usr/bin/env python3
"""Read-only first-pass inventory for heterogeneous log evidence.

The script inventories files, detects likely text/JSON/CSV/TSV formats, records
schema keys, samples timestamps, and emits a compact report. It does not copy
raw evidence into the output and does not assign an exfiltration outcome.
"""
from __future__ import annotations
import argparse, csv, json, os, re
from collections import Counter
from pathlib import Path

TS = re.compile(r"\b20\d{2}-\d{2}-\d{2}[T ][0-9:.+-Z]+")

def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument('--root', required=True)
    ap.add_argument('--output', required=True)
    ap.add_argument('--max-bytes-per-file', type=int, default=2_000_000)
    args = ap.parse_args()
    root = Path(args.root).resolve(); out = Path(args.output).resolve()
    if not root.is_dir(): raise SystemExit(f'root not found: {root}')
    out.mkdir(parents=True, exist_ok=True)
    formats = Counter(); keys = Counter(); timestamps = []
    inventory = []
    for p in sorted(root.rglob('*')):
        if not p.is_file(): continue
        rel = str(p.relative_to(root)); size = p.stat().st_size
        suffix = p.suffix.lower(); fmt = suffix.lstrip('.') or 'none'
        inventory.append((rel, size, fmt)); formats[fmt] += 1
        if size == 0 or size > args.max_bytes_per_file: continue
        try:
            with p.open('r', encoding='utf-8', errors='replace') as f:
                for i, line in enumerate(f):
                    if i >= 2000: break
                    m = TS.search(line)
                    if m and len(timestamps) < 5000: timestamps.append(m.group(0))
                    if line.lstrip().startswith('{'):
                        try:
                            obj = json.loads(line)
                            if isinstance(obj, dict): keys.update(obj.keys())
                        except json.JSONDecodeError: pass
        except OSError: pass
    with (out/'file-inventory.tsv').open('w', newline='', encoding='utf-8') as f:
        w=csv.writer(f, delimiter='\t'); w.writerow(['relative_path','bytes','format']); w.writerows(inventory)
    with (out/'schema-key-summary.csv').open('w', newline='', encoding='utf-8') as f:
        w=csv.writer(f); w.writerow(['key','observations']); w.writerows(keys.most_common())
    (out/'first-pass-summary.txt').write_text(
        f'files={len(inventory)}\nformats={dict(formats)}\n'
        f'sampled_timestamps={len(timestamps)}\n'
        'boundary=inventory only; no exfiltration outcome assigned\n', encoding='utf-8')
    return 0
if __name__ == '__main__': raise SystemExit(main())
