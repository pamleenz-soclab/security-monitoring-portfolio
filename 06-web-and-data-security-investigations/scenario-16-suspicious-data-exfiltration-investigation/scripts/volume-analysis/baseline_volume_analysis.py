#!/usr/bin/env python3
"""Calculate directional volume and low-and-slow rate from processed CSV."""
from __future__ import annotations
import argparse, csv
from datetime import datetime
from pathlib import Path

def main() -> int:
    ap=argparse.ArgumentParser(); ap.add_argument('--input', required=True); ap.add_argument('--output', required=True)
    a=ap.parse_args(); rows=list(csv.DictReader(Path(a.input).open(encoding='utf-8')))
    metrics={r['metric']:r['value'] for r in rows}
    req=int(metrics['outbound_request_wire_bytes']); resp=int(metrics['inbound_response_wire_bytes'])
    data=int(metrics['confirmed_source_object_bytes'])
    start=datetime.fromisoformat(metrics['first_observed']); end=datetime.fromisoformat(metrics['last_observed'])
    seconds=(end-start).total_seconds()
    report=[
        ['duration_seconds',f'{seconds:.3f}'],
        ['outbound_request_wire_bytes',str(req)],
        ['inbound_response_wire_bytes',str(resp)],
        ['confirmed_object_bytes',str(data)],
        ['outbound_wire_bytes_per_second',f'{req/seconds:.6f}'],
        ['wire_to_confirmed_data_ratio',f'{req/data:.6f}'],
        ['interpretation','wire bytes include protocol and encoding overhead; they are not the loss-volume figure'],
    ]
    out=Path(a.output); out.parent.mkdir(parents=True, exist_ok=True)
    with out.open('w', newline='', encoding='utf-8') as f: csv.writer(f).writerows([['metric','value'],*report])
    return 0
if __name__=='__main__': raise SystemExit(main())
