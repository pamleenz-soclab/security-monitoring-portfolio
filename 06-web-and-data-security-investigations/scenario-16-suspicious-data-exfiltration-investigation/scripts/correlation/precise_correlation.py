#!/usr/bin/env python3
"""Classify per-object transfer outcome from safe processed evidence."""
from __future__ import annotations
import argparse, csv
from pathlib import Path

def truth(v: str) -> bool: return str(v).strip().lower() in {'yes','true','1'}

def main() -> int:
    ap=argparse.ArgumentParser()
    ap.add_argument('--input', required=True, help='transfer-outcome-assessment.csv')
    ap.add_argument('--output', required=True)
    a=ap.parse_args(); src=Path(a.input); dst=Path(a.output)
    if not src.is_file(): raise SystemExit(f'input not found: {src}')
    rows=list(csv.DictReader(src.open(encoding='utf-8')))
    confirmed=attempted=unable=bytes_confirmed=0
    for r in rows:
        marker=int(r.get('completion_requests') or 0)>0
        receiver=truth(r.get('receiver_object_present',''))
        hash_match=truth(r.get('source_receiver_sha256_match',''))
        missing=bool((r.get('missing_chunk_indexes') or '').strip())
        if marker and receiver and hash_match and not missing:
            result='Confirmed exfiltration'; confirmed+=1
            bytes_confirmed += int(r.get('source_bytes') or 0)
        elif int(r.get('data_requests') or 0)>0 and not receiver:
            result='Attempted exfiltration'; attempted+=1
        else:
            result='Unable to confirm'; unable+=1
        r['recomputed_result']=result
    dst.parent.mkdir(parents=True, exist_ok=True)
    fields=list(rows[0])+['recomputed_result'] if rows else ['recomputed_result']
    with dst.open('w', newline='', encoding='utf-8') as f:
        w=csv.DictWriter(f, fieldnames=fields); w.writeheader(); w.writerows(rows)
    print(f'confirmed={confirmed} attempted={attempted} unable={unable} confirmed_bytes={bytes_confirmed}')
    return 0
if __name__=='__main__': raise SystemExit(main())
