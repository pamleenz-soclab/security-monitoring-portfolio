# Detection Improvement Backlog

Priority engineering opportunities:

1. ProgramData `.scr` → `cmd` → `sdclt` → `control` → hidden PowerShell.
2. Suspicious PowerShell lineage → high-access LSASS Event 10.
3. Source process → TCP/5985 → target 4624 → target `wsmprovhost`.
4. Network logon → ADMIN$ PSEXESVC write → IPC$ svcctl → 7045/service process.
5. PSEXESVC → Temp Python → repeated uncommon-destination connections.
6. User-context auto-start LocalSystem service → later SYSTEM execution.
7. Archive staging → SDelete cleanup.
8. hostui → registry-IEX → encoded hidden PowerShell.

Each item in the structured backlog includes a correlation key and false-positive considerations.

See `evidence/processed/detection-improvement-backlog.csv`.
