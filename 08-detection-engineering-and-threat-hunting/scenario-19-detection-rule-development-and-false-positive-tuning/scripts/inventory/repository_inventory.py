#!/usr/bin/env python3
"""Read-only lightweight inventory. Explicitly skips evidence/raw and evidence/working."""
from pathlib import Path
import sys
root=Path(sys.argv[1] if len(sys.argv)>1 else '.').resolve(); counts={'detections':0,'queries':0,'processed':0}
for p in root.rglob('*'):
    if not p.is_file(): continue
    s=p.as_posix()
    if '/evidence/raw/' in s or '/evidence/working/' in s or '/.git/' in s: continue
    if '/detections/' in s: counts['detections']+=1
    if '/queries/' in s: counts['queries']+=1
    if '/evidence/processed/' in s: counts['processed']+=1
print(counts)
