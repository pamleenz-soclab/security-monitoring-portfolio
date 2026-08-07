#!/usr/bin/env python3
import csv,sys
from pathlib import Path
if len(sys.argv)!=3:
    print('usage: regression_comparator.py OLD.csv NEW.csv'); sys.exit(2)
def load(p): return {r['fixture_id']:r for r in csv.DictReader(open(p,newline='',encoding='utf-8'))}
a,b=load(sys.argv[1]),load(sys.argv[2]); keys=sorted(set(a)|set(b)); changed=[]
for k in keys:
    oa=a.get(k,{}).get('actual_result','MISSING'); nb=b.get(k,{}).get('actual_result','MISSING')
    if oa!=nb: changed.append((k,oa,nb))
print('changed_results',len(changed))
for x in changed: print('\t'.join(x))
