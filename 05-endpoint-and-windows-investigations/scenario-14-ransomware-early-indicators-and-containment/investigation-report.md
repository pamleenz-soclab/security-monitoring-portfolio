# Investigation Report

## 1. Incident overview

The investigation examined a simulated ransomware event involving an ActiveMQ service, a temporary control executable, an encryption-oriented payload builder, interactive payload execution, recursive ransom-note creation, failed account-use attempts, remote-access evidence, and log-clearing commands.

The event affected one confirmed Windows host:

- Host: `EC2AMAZ-I41BETP`
- Private lab IP: `10.0.2.12`

The investigation found no evidence that ransomware executed on another host.

## 2. Evidence and reliability

Three independent telemetry sources were correlated:

1. Sysmon Operational
2. Windows Security
3. PowerShell Operational

The parser extracted 73,513 events with no parse errors. Short hostnames and FQDNs were normalised before correlation.

Reliability controls included:

- Source SHA-256 validation.
- Read-only raw evidence.
- Process GUID correlation instead of PID-only correlation.
- Host and timestamp constraints.
- Independent Sysmon and Security process confirmation.
- Separation of keyword candidates from command-bearing evidence.
- Explicit classification of missing telemetry.

## 3. Confirmed event sequence

### 3.1 Service-side and control-channel activity

Java and ActiveMQ-related connections were observed between `10.0.2.12` and `10.0.2.13` over TCP/61616 and TCP/8080. A temporary executable on `10.0.2.12` then established TCP/4444 to `10.0.2.13`.

This sequence is consistent with service exploitation followed by a reverse or control channel. Exact exploit content is unavailable.

### 3.2 Control process to command shell

The temporary executable `qSwUwejx.exe` later spawned `cmd.exe` as `SYSTEM`. Parent and child Process GUID values directly support this relationship.

### 3.3 Payload construction

The command shell launched `C:\Intel\builder.exe`. Its command line used an encryption-oriented build type, key input, configuration input, and output path for `C:\Intel\Build\LB3.exe`.

This confirms ransomware preparation and payload construction.

### 3.4 Remote session and interactive payload execution

Network and Security telemetry showed TCP/3389 from `10.0.1.10` to the affected host, explicit credentials, and an Administrator Logon Type 7 session event.

The existing Administrator Explorer process, Logon ID `0x11c15c`, launched `LB3.exe` at high integrity.

The evidence strongly supports manual execution through an existing or reconnected desktop session. A new Logon Type 10 event was not present.

### 3.5 File impact

The payload process created 183 files named:

`7duXYi3SC.README.txt`

The files were placed in 183 distinct local directories, including the Administrator Downloads tree and the extracted ActiveMQ directory tree.

This confirms recursive ransom-note deployment.

### 3.6 Account attempts

The payload PID generated seven failed Event ID 4625 logons against several domain-qualified accounts. No corresponding success was observed.

### 3.7 Log clearing and service-stop commands

Before payload construction, the Administrator context executed commands targeting:

- Terminal Services stop.
- System log clear.
- Application log clear.
- Security log clear.

Command execution is confirmed. Successful service termination and log clearing are not independently confirmed.

## 4. Impact assessment

### Confirmed impact

- Ransomware payload was constructed.
- Ransomware payload was executed.
- 183 ransom notes were written.
- One local host was directly affected.
- Administrative credentials and sessions require response.
- Event-log integrity may have been impaired.

### Unable to confirm

- Encryption of pre-existing files.
- Destruction or renaming of pre-existing files.
- Loss of file availability.
- Recovery inhibition.
- Shared-drive impact.
- Multi-host impact.
- Successful credential reuse.
- Data collection or exfiltration.

## 5. Alternative explanations considered

### Software deployment

High-volume Explorer, MSI, Java, Chocolatey, and PowerShell file activity occurred earlier in the dataset. These events were excluded from ransomware impact because they did not share the payload Process GUID and matched software deployment patterns.

### Legitimate audit-policy activity

`auditpol` commands enabled Kerberos success and failure auditing. They were not treated as defence evasion.

### Backup group activity

Events containing `Backup Operators` were not treated as recovery inhibition because they were local group and account events without a backup-destruction command.

### Network traffic alone

TCP/4444, TCP/3389, and external TCP/443 were not treated as proof of lateral movement or exfiltration without process, authentication, and transfer evidence.

## 6. ATT&CK assessment

### Supported mappings

| Technique | Assessment |
|---|---|
| T1059.003 — Windows Command Shell | Confirmed process chain |
| T1070.001 — Clear Windows Event Logs | Command execution confirmed; success unvalidated |
| T1489 — Service Stop | Terminal Services stop command confirmed; outcome unvalidated |
| T1021.001 — Remote Desktop Protocol | Transport and authentication evidence support remote-session use |

### Observed but not elevated to a confirmed final mapping

| Technique | Reason |
|---|---|
| T1059.001 — PowerShell | PowerShell activity exists, but much is environment preparation and the exact malicious role is incomplete |
| T1105 — Ingress Tool Transfer | External PowerShell and CertUtil connections exist, but complete download command and transferred object are not established |
| T1204.002 — Malicious File | Explorer launched the payload, but direct human action is inferred |

### Not mapped

| Technique | Reason |
|---|---|
| T1486 — Data Encrypted for Impact | File encryption is not independently confirmed |
| T1490 — Inhibit System Recovery | No command-bearing recovery-destruction evidence |
| T1562.001 — Impair Defenses | No security-product disablement evidence |
| T1021.002 — SMB/Windows Admin Shares | No TCP/445 or share evidence |
| T1569.002 — Service Execution | No malicious service creation or remote service execution |
| T1005 — Data from Local System | No independent data collection evidence |
| T1041 — Exfiltration Over C2 | No external upload evidence |

## 7. Scope

### Confirmed affected

- `EC2AMAZ-I41BETP`
- `10.0.2.12`
- `EC2AMAZ-I41BETP\Administrator`
- `NT AUTHORITY\SYSTEM`

### Requires investigation

- `10.0.1.10` — source of RDP and Administrator authentication evidence.
- `10.0.2.13` — ActiveMQ-related peer and TCP/4444 destination.

### Not confirmed affected

- `EC2AMAZ-TLJH2O4`
- `WIN-GM4EB5GIVO0`
- `WIN-QQ6SF2TB3S8`

## 8. Containment conclusion

Immediate host isolation is justified because payload execution and active file-impact markers are confirmed. A short volatile-capture window is appropriate, but continued local impact should not be allowed while waiting for a full memory acquisition.

The host should remain powered on unless network isolation and process termination fail.
