#!/usr/bin/env python3
"""Fixture provenance guard.
Final fixtures are checked in intentionally. This script verifies provenance fields rather than re-reading other scenarios or manufacturing new ground truth.
"""
import json,sys
from pathlib import Path
root=Path(__file__).resolve().parents[2]; bad=[]; count=0
for p in (root/'tests/fixtures').glob('*/*.jsonl'):
    for n,line in enumerate(p.read_text().splitlines(),1):
        if not line.strip(): continue
        count+=1; x=json.loads(line)
        for k in ('fixture_id','rule_id','source_scenario','source_file','synthetic_or_sanitised','expected_result','expected_classification','ground_truth_label','telemetry_label'):
            if k not in x or x[k] in ('',None): bad.append(f'{p}:{n}: missing {k}')
print(f'Fixture records checked: {count}')
if bad:
    print('\n'.join(bad)); sys.exit(2)
print('Fixture provenance check: PASSED')
