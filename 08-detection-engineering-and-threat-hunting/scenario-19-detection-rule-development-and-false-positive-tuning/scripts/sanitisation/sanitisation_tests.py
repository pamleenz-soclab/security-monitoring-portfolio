#!/usr/bin/env python3
import re,sys
from pathlib import Path
root=Path(__file__).resolve().parents[2]
patterns=[('private_key',re.compile(r'-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----')),('jwt',re.compile(r'eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}')),('authorization',re.compile(r'(?i)authorization:\s*bearer\s+\S+')),('aws_key',re.compile(r'AKIA[0-9A-Z]{16}'))]
bad=[]
for p in root.rglob('*'):
    if not p.is_file() or '/evidence/raw/' in p.as_posix() or '/evidence/working/' in p.as_posix(): continue
    if p.suffix.lower() in ('.png','.jpg','.jpeg','.zip'): continue
    try: text=p.read_text(encoding='utf-8')
    except: continue
    for name,rx in patterns:
        if rx.search(text): bad.append(f'{name}: {p.relative_to(root)}')
if bad:
    print('\n'.join(bad)); sys.exit(2)
print('Sanitisation tests: PASSED')
