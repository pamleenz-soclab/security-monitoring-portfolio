# Detection Engineering

## Detection objective

Detect a remote SMB authentication session that reaches `IPC$\svcctl`, creates a Windows service and causes Service Control Manager to spawn a shell or encoded PowerShell. The highest-fidelity alert is a correlation, not any one event in isolation.

## Telemetry requirements

| Telemetry | Events/fields | Purpose |
|---|---|---|
| Windows Security | 4624, 4672, 4697, 4776, 5140, 5145 | Account, source, logon type, Logon ID, share/pipe and service creator |
| Windows System | 7045, 7009 | Service installation and abnormal service start behaviour |
| Sysmon/EDR | 1, 3, 12, 13 | Process tree, network tuple and service registry activity |
| PowerShell | 4104 and preferably 4103 | Decoded script behaviour and command context |
| Network/EDR | TCP/445 and post-execution egress | Independent host-to-host and callback confirmation |

Advanced Audit Policy must include successful Logon, Special Logon, Security System Extension, Account Logon/Credential Validation, File Share and Detailed File Share auditing. Process command-line auditing and PowerShell Script Block Logging materially improve fidelity.

## Detection layers

### Layer 1 — remote SCM access

Trigger on Event ID 5145 where the share is `IPC$` and `RelativeTargetName` is `svcctl`. This is a useful lead but commonly occurs during legitimate remote administration.

Enrich with:

- source IP/host and account;
- approved management subnets/tools;
- whether the account normally administers the target;
- 4624 Type 3 and 4672 under the same Logon ID;
- 4697/7045 on the target within two minutes.

### Layer 2 — suspicious service ImagePath

Trigger on 4697 or 7045 when the service command contains combinations such as:

- `%COMSPEC%` or `cmd.exe /C`;
- PowerShell or `pwsh`;
- `-enc`, `-EncodedCommand`, hidden-window flags or download cradles;
- user-writable paths, pipes or high-entropy service names.

This layer is stronger than service-name entropy alone. Legitimate product services can have opaque names, but a service that launches nested shells and encoded PowerShell is much less common.

### Layer 3 — Service Control Manager process ancestry

Trigger on `services.exe` spawning `cmd.exe`, `powershell.exe`, `pwsh.exe`, `wscript.exe`, `cscript.exe`, `mshta.exe` or similar interpreters. Increase severity when:

- the child command is encoded/hidden;
- the process immediately makes a network connection;
- PowerShell 4104 shows AMSI/logging bypass, download or in-memory execution;
- a preceding remote Type 3 logon and `svcctl` access exist.

### Layer 4 — high-confidence sequence correlation

Within two minutes on the same target:

1. 4624 Type 3 from a workstation or unapproved source;
2. 5145 `IPC$\svcctl` under the same account/Logon ID;
3. 4697 or 7045 service installation;
4. `services.exe` child shell/PowerShell;
5. optional outbound connection from the child process.

This correlation should be **High** severity. If the account is privileged, the target is high value, or the child establishes C2, escalate to **Critical**.

## Rule content

- `detections/sigma/win_system_suspicious_remote_service_shell_stager.yml`
- `detections/sigma/win_services_spawn_suspicious_shell.yml`
- `detections/sigma/win_security_smb_svcctl_named_pipe_access.yml`
- `detections/splunk/smbexec_lateral_movement_correlation.spl`
- `detections/microsoft-sentinel/smbexec_lateral_movement_correlation.kql`

The Sigma rules represent portable single-event behaviours. The Splunk and Sentinel examples perform multi-event correlation and must be adapted to the organisation's field mapping and indexes/tables.

## Tuning and false positives

Expected sources include:

- SCCM/MECM, endpoint-management and software-deployment servers;
- vulnerability scanners and EDR response tooling;
- backup agents and remote support platforms;
- authorised administrators using Service Control Manager;
- red-team and penetration-test infrastructure.

Tune by approved **source + account + target group + time window + service/ImagePath pattern**, not by globally excluding `svcctl` or `services.exe`. Keep an alert when an approved management source launches an encoded interpreter or generates unexpected egress.

## Validation cases

| Test | Expected outcome |
|---|---|
| OTRF Empire Invoke SMBExec | All three Sigma behaviours and the correlation match |
| Normal service start of an existing service | No 7045/4697 creation; no correlation |
| Approved deployment creates a signed binary service | 7045 may match baseline but suspicious ImagePath rule should not |
| Remote admin creates a service using `cmd /c powershell -enc` | High-confidence alert |
| Local service creation with no 4624/5145 | Behavioural service alert only; no lateral-movement correlation |

## MITRE ATT&CK mapping

### Telemetry-supported

- `T1021.002` — SMB/Windows Admin Shares
- `T1569.002` — Service Execution
- `T1059.003` — Windows Command Shell
- `T1059.001` — PowerShell
- `T1562.001` — Impair Defenses, based on the AMSI/logging impairment behaviour in Event 4104
- `T1071.001` — Web Protocols, based on the target PowerShell HTTP connection

### Simulation-ground-truth supported

- `T1550.002` — Pass the Hash. The source-side simulation command supplied an NTLM hash, but target/network telemetry alone cannot distinguish hash use from another successful NTLM credential source.

RDP, WinRM and WMI remote execution are not mapped because they are not supported by the confirmed chain.

## References

- [Sigma rule specification](https://sigmahq.io/sigma-specification/specification/sigma-rules-specification.html)
- [Sigma log sources](https://sigmahq.io/docs/basics/log-sources.html)
- [MITRE ATT&CK T1021.002](https://attack.mitre.org/techniques/T1021/002/)
- [MITRE ATT&CK T1569.002](https://attack.mitre.org/techniques/T1569/002/)
- [Microsoft Event 4697 guidance](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4697)

