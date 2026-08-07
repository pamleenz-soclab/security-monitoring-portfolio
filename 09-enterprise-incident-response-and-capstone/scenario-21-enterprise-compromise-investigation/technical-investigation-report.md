# Technical Investigation Report

## Initial lead

The primary lead is `HOSTJSON:373`: Sysmon Event 1 on SCRANTON at `2020-05-02T02:55:56.157Z`, where `DMEVALS\pbeesly` launched an unusual `.scr` from `C:\ProgramData\victim`. The public processed evidence normalizes the display of the filename to `<RLO-like>.scr`; the raw source retains the original encoded rendering.

## Execution reconstruction

Exact `ParentProcessGuid` relationships establish:

`.scr -> cmd.exe -> sdclt.exe -> control.exe -> hidden PowerShell`

The hidden PowerShell reads pixel values from `monkey.png`, reconstructs bytes, and invokes recovered content in memory. This is direct execution telemetry, not an ATT&CK-ground-truth inference.

The same PowerShell process also has exact-ProcessGuid network activity to lab infrastructure.

## Credential access

`HOSTJSON:53270` is Sysmon Event 10 showing:

- `SourceImage = PowerShell.exe`
- `SourceProcessGuid = {47ab858c-e1e4-5eac-b803-000000000400}`
- `TargetImage = lsass.exe`
- `GrantedAccess = 0x1fffff`

The SourceProcessGuid exactly matches the hidden malicious PowerShell process, making this a strong incident correlation. The evidence supports credential-access behavior, but no credential material output is available.

Two other high-access LSASS candidates were rejected during precision review because their source processes were normal `wininit.exe` and `csrss.exe`.

A separate PowerShell `Export-PfxCertificate` event was also reviewed. It explicitly terminated with `Cannot export non-exportable private key`; certificate theft is therefore **attempted and unsuccessful**, not successful.

## Persistence and elevated execution

System Event 7045 on SCRANTON installed:

- Service: `Java(TM) Virtual Machine Support Service`
- Image path: `C:\Windows\System32\javamtsup.exe`
- Start type: auto start
- Service account: LocalSystem

Later Sysmon telemetry shows that same path launched by `services.exe` as `NT AUTHORITY\SYSTEM`, then spawning `rundll32.exe`. This establishes persistence execution and a SYSTEM-level outcome. The exact privilege-acquisition mechanism is not fully reconstructed.

## Lateral movement

### WinRM

A child PowerShell on SCRANTON used the exact ProcessGuid `{47ab858c-e374-5eac-d803-000000000400}` for traffic to NASHUA `10.0.1.6:5985`.

At NASHUA, a same-time Kerberos network logon for `pbeesly` was followed by `wsmprovhost.exe` under exact `LogonId 0x85aad2`.

The source-side process-to-network relationship is Strong. The target logon-to-process relationship is Strong. The source-to-target bridge is rated Moderate because no stable identifier spans both hosts.

### SMB / PsExec

A later NASHUA session records source IP `10.0.1.4`, `pbeesly`, and stable Logon IDs across:

- network logon,
- ADMIN$ activity,
- `PSEXESVC.exe` access with WriteData/AppendData,
- `IPC$\svcctl`,
- PSEXESVC service creation.

A separate 5145 event for `Temp\python.exe` requested only `ReadAttributes`; it is explicitly **not** used as proof that the file was written/copied.

PSEXESVC later launches `C:\Windows\Temp\python.exe`, and exact parent/child ProcessGuids confirm that process relationship.

## Command and control

The initial `.scr`, malicious PowerShell, and NASHUA Python processes all have process-attributed Sysmon Event 3 activity to lab-private infrastructure.

The NASHUA Python descendant generates **348** connections to `192.168.0.4:8443` using one exact ProcessGuid. Later encoded PowerShell activity on SCRANTON is followed by communication to `192.168.0.4:443`.

These observations support incident-correlated command-and-control behavior within endpoint telemetry. Independent Zeek logs cannot validate the same events because their timestamps do not overlap the host incident window.

## Collection and cleanup

`Rar.exe` executes on NASHUA with password-protected archive staging involving `working.zip`. The archive password is redacted from public processed evidence. Shortly afterward, SDelete removes `Rar.exe`. Earlier SDelete activity targeted the initial `.scr`.

This supports Collection and Defense Evasion. It does not prove the archive contained sensitive data or that it was exfiltrated.

## Final boundary

The investigation confirms a multi-stage endpoint compromise but stops before Initial Access, successful credential extraction, Exfiltration, or ATT&CK/business Impact because those outcomes are not supported by the source-derived telemetry.
