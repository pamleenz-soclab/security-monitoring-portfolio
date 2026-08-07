#!/usr/bin/env python3
import csv
from pathlib import Path
p=Path(__file__).resolve().parents[2]/'evidence/processed/cross-platform-semantic-comparison.csv'
rows=list(csv.DictReader(p.open()))
assert rows, 'comparison table empty'
for r in rows:
    assert r['semantic_status'] in ('Aligned candidate','Semantic approximation','Not equivalent','Primitive only','Not applicable')
print(f'Semantic comparison records: {len(rows)}')
print('Semantic comparison schema: PASSED')
