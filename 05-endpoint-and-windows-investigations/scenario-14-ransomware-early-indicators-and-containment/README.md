# Scenario 14 — Ransomware Early Indicators and Containment

**Priority:** Flagship  
**Investigation type:** Endpoint, identity, network, file-impact, and containment analysis  
**Dataset:** Splunk Attack Data — ActiveMQ Exploit LockBit Ransomware  
**Investigation date:** 2026-08-06  
**Evidence time window:** 2026-04-24  
**Primary affected host:** `EC2AMAZ-I41BETP` (`10.0.2.12`, private lab address)

## Executive summary

This investigation confirmed ransomware preparation, payload construction, payload execution, recursive ransom-note deployment, attempted account use, and log-clearing commands on one Windows host.

The evidence supports the following sequence:

1. Activity consistent with interaction with an ActiveMQ service was observed over TCP/61616 and TCP/8080.
2. A temporary executable, `qSwUwejx.exe`, established a TCP/4444 connection and later spawned `cmd.exe` as `SYSTEM`.
3. `cmd.exe` launched a builder process that produced `C:\Intel\Build\LB3.exe` using an encryption-oriented build profile.
4. An existing Administrator desktop session launched `LB3.exe` from `explorer.exe`.
5. The payload created `7duXYi3SC.README.txt` in 183 distinct local directories.
6. The payload generated several failed authentication attempts against domain-qualified account names.
7. Commands were executed to stop Terminal Services and clear the System, Application, and Security event logs.

The supplied telemetry does **not** independently prove that pre-existing files were encrypted, renamed, deleted, or rendered inaccessible. No recovery-inhibition commands, SMB spread, shared-drive impact, multi-host ransomware execution, data staging, or data exfiltration were confirmed.

## Final classification

| Investigation question | Result |
|---|---|
| Ransomware preparation | **Confirmed** |
| Payload construction | **Confirmed** |
| Payload execution | **Confirmed** |
| Ransom-note deployment | **Confirmed** |
| File encryption | **Unable to confirm** |
| File deletion | **Not observed** |
| File rename | **Not available / not observed** |
| Recovery inhibition | **Not observed** |
| Log-clearing command execution | **Confirmed** |
| Terminal Services stop command | **Confirmed** |
| RDP transport to the affected host | **Confirmed** |
| RDP-driven manual payload execution | **Strongly inferred** |
| Successful credential reuse | **Not observed** |
| SMB lateral movement | **Not observed** |
| Multi-host ransomware impact | **Not observed** |
| Data staging or exfiltration | **Not confirmed / not observed** |

## Evidence basis

The investigation used three independent Windows telemetry sources:

- Sysmon Operational events for process creation, network connections, and file creation.
- Windows Security events for process creation, authentication, explicit credential use, and failed logons.
- PowerShell Operational events for script-block and execution context review.

A total of **73,513 events** were parsed with **zero parser errors**:

| Source | Events |
|---|---:|
| Sysmon | 13,462 |
| Windows Security | 16,946 |
| PowerShell | 43,105 |

## High-confidence process relationships

### Control-to-build path

```text
qSwUwejx.exe
  └─ cmd.exe [SYSTEM]
       └─ builder.exe
            └─ creates C:\Intel\Build\LB3.exe
```

### Interactive execution path

```text
userinit.exe
  └─ explorer.exe [Administrator, Logon ID 0x11c15c]
       └─ LB3.exe
            ├─ creates 183 ransom-note files
            └─ generates failed authentication attempts
```

The builder created the payload file, but the payload was executed separately from an Administrator Explorer session. The evidence does not show `builder.exe` directly launching `LB3.exe`.

## Key identifiers

| Field | Value |
|---|---|
| Affected logical host | `EC2AMAZ-I41BETP` |
| Affected host IP | `10.0.2.12` |
| Suspected service-side peer | `10.0.2.13` |
| Remote-management source | `10.0.1.10` |
| Temporary control executable | `C:\Users\ADMINI~1\AppData\Local\Temp\2\qSwUwejx.exe` |
| Control-process GUID | `{0741354c-35c1-69eb-4e05-000000006702}` |
| Builder-process GUID | `{0741354c-4630-69eb-5d07-000000006702}` |
| Payload-process GUID | `{0741354c-46aa-69eb-7f07-000000006702}` |
| Payload PID | `1844` / `0x734` |
| Payload account | `EC2AMAZ-I41BETP\Administrator` |
| Payload Logon ID | `0x11c15c` |
| Payload SHA-256 | `8ADCB1AE01F295EBD4A50B6BB41F9FE05AE90FC7E655002A8C400F7F9D05A582` |
| Ransom-note name | `7duXYi3SC.README.txt` |
| Ransom-note count | `183` |
| Distinct note directories | `183` |

All IP addresses in this repository are private laboratory addresses or dataset values. They are not presented as public malicious infrastructure.

## Containment decision

The recommended response is:

1. Isolate `EC2AMAZ-I41BETP` from the network while preserving power.
2. Capture rapid volatile evidence, then terminate `LB3.exe`.
3. Terminate affected Administrator sessions and reset or temporarily disable the exposed administrative credentials.
4. Investigate `10.0.1.10` and `10.0.2.13`.
5. Block TCP/4444 and restrict RDP, SMB, WinRM, and WMI to the affected host.
6. Remove the affected host's access to shared resources while scope is validated.
7. Do not power off unless isolation and process termination fail or file impact continues.

See [containment-decision-record.md](containment-decision-record.md) for the business and forensic trade-offs.

## Repository structure

```text
.
├── README.md
├── dataset-decision-record.md
├── evidence-inventory.md
├── triage-note.md
├── investigation-notes.md
├── investigation-report.md
├── recommended-actions.md
├── containment-decision-record.md
├── recovery-plan.md
├── detection-engineering.md
├── source-and-license-record.md
├── diagrams/
├── detections/
│   └── sigma/
├── queries/
│   ├── sentinel/
│   └── splunk/
├── scripts/
├── evidence/
│   ├── raw/
│   ├── working/
│   └── processed/
```

## Safety and publication notes

- Raw logs are not included.
- No malware sample or executable is included.
- No credential, token, or secret is included.
- Potentially dangerous command details are reduced to detection-relevant summaries in published evidence.
- The original dataset remains subject to its source licence and attribution requirements.
- `evidence/raw/` and `evidence/working/` are intentionally ignored by Git.
