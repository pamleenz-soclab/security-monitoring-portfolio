#!/usr/bin/env python3
"""Generate a minimal publishable evidence set from Scenario 15 working outputs.

This script intentionally emits only bounded fragments and excludes Cookie,
Authorization, token and session values. It is designed for offline analysis.
"""
from __future__ import annotations
import argparse, csv, re
from pathlib import Path
from urllib.parse import unquote_plus


def clean(value: str, limit: int = 100) -> str:
    value = re.sub(r'(?i)(cookie|authorization|token|session)[^\s,;]*', '[REDACTED]', value or '')
    value = re.sub(r'[\r\n\t]+', ' ', value).strip()
    return value if len(value) <= limit else value[:limit-1] + '…'


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument('scenario_dir', type=Path)
    args = ap.parse_args()
    first = args.scenario_dir / 'evidence/working/first-pass'
    precise = args.scenario_dir / 'evidence/working/precise-validation'
    out = args.scenario_dir / 'evidence/processed'
    out.mkdir(parents=True, exist_ok=True)
    required = [first/'transactions.csv', first/'rule-hits.csv', precise/'dominant-source-sequence.csv']
    missing = [str(p) for p in required if not p.exists()]
    if missing:
        raise SystemExit('Missing working outputs: ' + ', '.join(missing))

    with (precise/'dominant-source-sequence.csv').open(newline='', encoding='utf-8') as f, \
         (out/'web-request-timeline-reproduced.csv').open('w', newline='', encoding='utf-8') as g:
        reader = csv.DictReader(f)
        fields = ['timestamp_utc','txid','client_ip','host','method','path','sqli_rule_ids','response_status','duration_ms','signal_classification','sanitised_target_fragment']
        writer = csv.DictWriter(g, fieldnames=fields); writer.writeheader()
        for row in reader:
            writer.writerow({
                'timestamp_utc':row.get('timestamp_utc',''), 'txid':row.get('txid',''),
                'client_ip':row.get('client_ip',''), 'host':row.get('host',''),
                'method':row.get('method',''), 'path':row.get('path',''),
                'sqli_rule_ids':row.get('sqli_rule_ids',''), 'response_status':row.get('response_status',''),
                'duration_ms':row.get('duration_ms',''), 'signal_classification':row.get('signal_classification',''),
                'sanitised_target_fragment':clean(unquote_plus(row.get('raw_target','')))
            })
    print(out/'web-request-timeline-reproduced.csv')
    return 0

if __name__ == '__main__':
    raise SystemExit(main())
