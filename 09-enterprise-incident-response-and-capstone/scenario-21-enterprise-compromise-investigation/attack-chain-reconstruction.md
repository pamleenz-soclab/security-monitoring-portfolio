# Attack-Chain Reconstruction

Only evidence-supported relationships are shown.

```text
SCRANTON unusual .scr
  └─ Strong: exact ParentProcessGuid
     cmd.exe
       └─ Strong
          sdclt.exe
            └─ Strong
               control.exe
                 └─ Strong
                    hidden PowerShell
                      ├─ Strong: exact SourceProcessGuid -> LSASS access
                      ├─ Strong: child PowerShell lineage
                      │    └─ Strong source-side -> NASHUA:5985
                      │         └─ Moderate cross-host bridge
                      │              └─ Strong target LogonId -> wsmprovhost
                      └─ process-attributed C2-like communications

Later NASHUA SMB/PsExec session
  network logon
    └─ Strong LogonId/source-IP
       ADMIN$ PSEXESVC.exe WriteData
         └─ svcctl
            └─ PSEXESVC service/process
               └─ Strong ParentProcessGuid
                  python.exe
                    └─ Strong ProcessGuid
                       348 connections -> 192.168.0.4:8443
```

In parallel, SCRANTON receives an auto-start LocalSystem service that later executes as SYSTEM. NASHUA performs archive staging and cleanup.

The reconstruction stops before Exfiltration and Impact because outcome evidence is absent.
