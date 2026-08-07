#!/usr/bin/env python3
import subprocess,sys
from pathlib import Path
root=Path(__file__).resolve().parents[2]
repo=None
for p in [root,*root.parents]:
    if (p/'.git').exists(): repo=p; break
if repo is None:
    print('Git-aware validation: standalone package mode; no enclosing .git found.')
    for d in (root/'evidence/raw',root/'evidence/working'):
        extra=[p for p in d.iterdir() if p.name!='.gitkeep']
        if extra: print('FAILED: standalone raw/working contains files'); sys.exit(2)
    print('Git-aware validation: PASSED'); sys.exit(0)
rel=root.relative_to(repo)
for sub in ('evidence/raw','evidence/working'):
    p=root/sub
    probe=p/'.scenario19-ignore-probe'
    r=subprocess.run(['git','-C',str(repo),'check-ignore','-q','--no-index',str(probe)],capture_output=True)
    if r.returncode!=0:
        print(f'FAILED: {rel/sub} is not ignored'); sys.exit(2)
tracked=subprocess.run(['git','-C',str(repo),'ls-files',str(rel/'evidence/raw'),str(rel/'evidence/working')],capture_output=True,text=True).stdout.strip().splitlines()
tracked=[x for x in tracked if not x.endswith('/.gitkeep')]
if tracked:
    print('FAILED: tracked raw/working files:',*tracked,sep='\n'); sys.exit(2)
print('Git-aware validation: PASSED')
