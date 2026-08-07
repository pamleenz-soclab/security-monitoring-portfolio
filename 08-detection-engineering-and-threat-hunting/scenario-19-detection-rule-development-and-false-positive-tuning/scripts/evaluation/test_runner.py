#!/usr/bin/env python3
import argparse,csv,json,sys
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parent))
from local_rule_evaluator import evaluate

def load(root):
    out=[]
    for p in sorted((root/'tests/fixtures').glob('*/*.jsonl')):
        for line in p.read_text(encoding='utf-8').splitlines():
            if line.strip(): out.append(json.loads(line))
    return out

def classification(case,actual):
    if actual=='Unable to evaluate': return 'Unable to test'
    if actual=='Match':
        if case['expected_classification']=='Benign Positive': return 'Benign Positive'
        if case['expected_classification']=='True Positive': return 'True Positive'
        if case['expected_result']=='No match': return 'False Positive'
        return case['expected_classification']
    if actual=='No match':
        if case['expected_result']=='Match': return 'False Negative'
        return 'True Negative' if case['expected_classification']=='True Negative' else case['expected_classification']

def main():
    ap=argparse.ArgumentParser(); ap.add_argument('--root',default=str(Path(__file__).resolve().parents[2])); ap.add_argument('--output',default='')
    a=ap.parse_args(); root=Path(a.root); cases=load(root); rows=[]
    for c in cases:
        actual=evaluate(c); rows.append({'fixture_id':c['fixture_id'],'rule_id':c['rule_id'],'expected_result':c['expected_result'],'actual_result':actual,'expected_classification':c['expected_classification'],'actual_classification':classification(c,actual),'pass':str(actual==c['expected_result']).upper(),'source_scenario':c['source_scenario'],'synthetic_or_sanitised':c['synthetic_or_sanitised'],'notes':c.get('notes','')})
    out=Path(a.output) if a.output else root/'tests/results/final-v3-test-results.csv'; out.parent.mkdir(parents=True,exist_ok=True)
    with out.open('w',newline='',encoding='utf-8') as f:
        w=csv.DictWriter(f,fieldnames=rows[0].keys()); w.writeheader(); w.writerows(rows)
    passed=sum(r['pass']=='TRUE' for r in rows); print(f'V3 regression: {passed}/{len(rows)} passed'); print(f'Output: {out}')
    if passed!=len(rows): sys.exit(2)
if __name__=='__main__': main()
