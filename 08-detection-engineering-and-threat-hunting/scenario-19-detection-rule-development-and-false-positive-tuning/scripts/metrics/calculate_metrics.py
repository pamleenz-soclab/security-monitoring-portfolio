#!/usr/bin/env python3
import csv,sys
from pathlib import Path
root=Path(__file__).resolve().parents[2]; p=root/'tests/results/final-v3-test-results.csv'
rows=list(csv.DictReader(p.open()))
print('fixture_count',len(rows)); print('regression_passes',sum(r['pass']=='TRUE' for r in rows));
for c in ('True Positive','Benign Positive','True Negative','False Positive','False Negative','Unable to test'):
    print(c, sum(r['actual_classification']==c for r in rows))
print('NOTE: precision/recall/FPR are not reported as production estimates; fixtures are curated and not an independent enterprise population.')
