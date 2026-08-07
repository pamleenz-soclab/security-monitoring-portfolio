#!/usr/bin/env python3
"""Create a review report for publishable processed evidence without modifying it."""
from __future__ import annotations
import argparse, json, re
from pathlib import Path
UUID=re.compile(r'\b[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}\b',re.I)
UPN=re.compile(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b')
FORBIDDEN=['Bearer ','-----BEGIN PRIVATE KEY-----','-----BEGIN CERTIFICATE-----','Authorization:','access_token','refresh_token']
def main():
    ap=argparse.ArgumentParser(); ap.add_argument('--input',required=True,type=Path); ap.add_argument('--report',required=True,type=Path)
    a=ap.parse_args(); findings=[]
    for p in a.input.rglob('*'):
        if not p.is_file(): continue
        try: t=p.read_text(encoding='utf-8')
        except UnicodeDecodeError: findings.append({'file':str(p),'type':'binary'}); continue
        for m in FORBIDDEN:
            if m.lower() in t.lower(): findings.append({'file':str(p),'type':'forbidden_marker','value':m})
        for u in set(UPN.findall(t)):
            if not u.endswith('@synthetic.example'): findings.append({'file':str(p),'type':'non_synthetic_upn','value':u})
        # Synthetic UUIDs are allowed but reported for review.
        for v in set(UUID.findall(t)):
            findings.append({'file':str(p),'type':'synthetic_uuid_present','value':v})
    result={'status':'REVIEW' if findings else 'PASS','findings':findings}
    a.report.parent.mkdir(parents=True,exist_ok=True); a.report.write_text(json.dumps(result,indent=2)+'\n')
    print(json.dumps({'status':result['status'],'finding_count':len(findings),'report':str(a.report)},indent=2))
    return 0
if __name__=='__main__': raise SystemExit(main())
