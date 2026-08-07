#!/usr/bin/env python3
"""Validate the final Scenario 18 portfolio in standalone or Git-aware mode."""

from __future__ import annotations
import argparse, csv, hashlib, json, re, subprocess, sys
from pathlib import Path

REQUIRED = [
    'README.md','dataset-decision-record.md','evidence-inventory.md','source-and-license-record.md',
    'triage-note.md','investigation-notes.md','investigation-report.md','executive-summary.md',
    'recommended-actions.md','containment-decision-record.md','revocation-and-recovery-plan.md',
    'detection-engineering.md','false-positive-tuning.md','validation-checklist.md',
    'github-publishing-guide.md','PACKAGE-MANIFEST.tsv',
    'evidence/processed/cloud-privilege-event-timeline.csv',
    'evidence/processed/principal-and-object-mapping.csv',
    'evidence/processed/cloud-privilege-abuse-assessment.csv',
    'scripts/parsing/first_pass_parser.py',
    'scripts/correlation/precise_cloud_privilege_correlation.py',
    'scripts/correlation/permission_risk.py',
    'scripts/validation/sanitisation_test.py',
]
FORBIDDEN = ['-----BEGIN PRIVATE KEY-----','Bearer ','Authorization: Bearer','refresh_token=','access_token=','client_secret=']

def git(repo: Path, *args: str):
    return subprocess.run(['git','-C',str(repo),*args], text=True, capture_output=True)

def main() -> int:
    ap=argparse.ArgumentParser()
    ap.add_argument('--scenario-dir', required=True, type=Path)
    ap.add_argument('--repo-root', type=Path)
    ap.add_argument('--standalone', action='store_true')
    args=ap.parse_args()
    root=args.scenario_dir.resolve()
    errors=[]; warnings=[]
    for rel in REQUIRED:
        if not (root/rel).is_file(): errors.append(f'Missing required file: {rel}')
    for local_dir in ['evidence/raw','evidence/working']:
        d=root/local_dir
        if not d.is_dir(): errors.append(f'Missing directory: {local_dir}'); continue
        if args.standalone:
            extras=[p for p in d.rglob('*') if p.is_file() and p.name!='.gitkeep']
            if extras: errors.append(f'Standalone {local_dir} contains local evidence: {extras}')
    for p in root.rglob('*'):
        if not p.is_file() or p.suffix in {'.zip','.png','.jpg','.jpeg','.webp','.sqlite'}: continue
        try: text=p.read_text(encoding='utf-8')
        except UnicodeDecodeError: continue
        rel_text=str(p.relative_to(root))
        if not rel_text.startswith('scripts/validation/'):
            for marker in FORBIDDEN:
                if marker.lower() in text.lower(): errors.append(f'Forbidden secret/token marker in {rel_text}: {marker}')
        for n,line in enumerate(text.splitlines(),1):
            if line.rstrip()!=line: errors.append(f'Trailing whitespace: {p.relative_to(root)}:{n}')
    manifest=root/'PACKAGE-MANIFEST.tsv'
    if manifest.is_file():
        rows=list(csv.DictReader(manifest.open(encoding='utf-8'), delimiter='\t'))
        listed={r['relative_path'] for r in rows}
        for r in rows:
            p=root/r['relative_path']
            if not p.is_file(): errors.append(f'Manifest file missing: {r["relative_path"]}'); continue
            if hashlib.sha256(p.read_bytes()).hexdigest()!=r['sha256']: errors.append(f'Manifest hash mismatch: {r["relative_path"]}')
        actual={str(p.relative_to(root)) for p in root.rglob('*') if p.is_file() and p.name!='PACKAGE-MANIFEST.tsv'}
        if listed!=actual:
            errors.append(f'Manifest membership mismatch: missing={sorted(actual-listed)}, extra={sorted(listed-actual)}')
    if args.repo_root:
        repo=args.repo_root.resolve()
        try: rel=root.relative_to(repo)
        except ValueError: errors.append('Scenario directory is not under repo root'); rel=Path('.')
        tracked=git(repo,'ls-files','--',str(rel/'evidence/raw'),str(rel/'evidence/working'))
        bad=[x for x in tracked.stdout.splitlines() if x and not x.endswith('.gitkeep')]
        if bad: errors.append('Raw/working evidence tracked: '+', '.join(bad))
        for d in [root/'evidence/raw',root/'evidence/working']:
            for p in d.rglob('*'):
                if p.is_file() and p.name!='.gitkeep' and git(repo,'check-ignore','-q',str(p)).returncode!=0:
                    errors.append(f'Local evidence not ignored: {p.relative_to(repo)}')
    result={'status':'PASS' if not errors else 'FAIL','errors':errors,'warnings':warnings}
    print(json.dumps(result,indent=2))
    return 0 if not errors else 1
if __name__=='__main__': raise SystemExit(main())
