# IOC and Observable Analysis

The most useful observables are behavioral and environment-specific rather than portable threat-intelligence IOCs.

High-value examples:

- ProgramData `.scr` process lineage.
- Java-named auto-start LocalSystem service and `javamtsup.exe`.
- ADMIN$ `PSEXESVC.exe` write + `svcctl` + service execution.
- `C:\Windows\Temp\python.exe` launched by PSEXESVC.
- Exact Python ProcessGuid producing repeated `192.168.0.4:8443` connections.
- RAR staging followed by SDelete.

`192.168.0.4` and `192.168.0.5` are RFC1918 lab addresses. They are evidence for this case, not globally malicious public IOCs.

See `evidence/processed/ioc-observable-register.csv`.
