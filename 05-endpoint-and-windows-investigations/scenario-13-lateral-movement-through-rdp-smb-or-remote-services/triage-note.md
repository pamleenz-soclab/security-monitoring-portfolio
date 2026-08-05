# Triage Note

## Alert summary

- **Alert:** Possible SMB-based lateral movement and remote service execution
- **Classification:** True Positive
- **Severity:** High
- **Source:** `WORKSTATION5` (`172.18.39.5`)
- **Target:** `WORKSTATION6` (`172.18.39.6`)
- **Account:** `THESHIRE\pgustavo`
- **Target logon:** Type 3, NTLM, Logon ID `0x2074186`
- **Remote mechanism:** SMB2 `IPC$` + `svcctl` + SVCCTL RPC
- **Execution context:** `NT AUTHORITY\SYSTEM`

## Why this is malicious

The same target Logon ID links a successful NTLM network logon, special privileges, `IPC$` access, `svcctl` access and installation of temporary service `PGUJLOAKFQFVOMHGFQPX`. The service command launches nested shells and encoded PowerShell. The resulting SYSTEM PowerShell attempts logging/AMSI impairment, connects to the private lab listener and spawns `whoami.exe`.

Two endpoint PCAPs independently show the same TCP/445 flow, NTLMSSP authentication, `IPC$`, `svcctl` and remote SCM operations. The SVCCTL start response reports a timeout, but target process telemetry proves successful command execution.

## Immediate actions

1. Validate the account, source, target and timestamp against change tickets, software-deployment records and administrator activity. The supplied telemetry does not contain authorization records.
2. Isolate `WORKSTATION5` and `WORKSTATION6`, preserving EDR access and volatile evidence where operationally possible.
3. Disable or reset `THESHIRE\pgustavo` according to identity policy, force supported session invalidation/logoff, and review privileged group membership.
4. In a real incident, block the corresponding confirmed destination and URI. `10.10.10.5` is a private address used by this lab simulation and is not presented as public malicious infrastructure.
5. Preserve Security, System, Sysmon, PowerShell and relevant domain-controller logs, plus packet and memory/EDR evidence.
6. Hunt for the service name, `svcctl` access, encoded PowerShell under `services.exe`, the two ProcessGuids and account reuse across other hosts.

## Scope statement

Confirmed internal lateral movement stops at `WORKSTATION6` in the supplied capture. `MORDORDC` performed successful credential validation but has no evidence of compromise. Source-side attack activity is present on `WORKSTATION5`; its initial compromise occurred outside the captured window.
