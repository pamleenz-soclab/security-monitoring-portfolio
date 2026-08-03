# Detection Engineering

## Detection objective

Detect high-risk scheduled-task persistence while avoiding alerts on every legitimate task created by Windows, software installers, or endpoint-management systems.

The strongest detection is behavioural and correlated. A task name or Event ID `4698` alone is not sufficient.

## High-confidence behaviours

### 1. Suspicious `schtasks.exe` creation command

Alert when one process command combines:

- `schtasks.exe /Create`;
- `SYSTEM` run account;
- `ONLOGON` trigger;
- PowerShell or `pwsh` task action;
- hidden window, encoded content, Base64 decoding, registry retrieval, or `IEX`/`Invoke-Expression`.

This logic is implemented in:

- `detections/sigma/win_suspicious_schtasks_system_logon_powershell.yml`

Dataset validation produced two matching telemetry records representing one unique process: one Sysmon Event ID `1` and one Security Event ID `4688`.

### 2. Task-launched PowerShell registry loader

Alert when PowerShell is created by `svchost.exe` or a known Task Scheduler host context and its command line combines:

- hidden or non-interactive execution;
- registry retrieval from `HKLM`;
- `FromBase64String`;
- `IEX` or `Invoke-Expression`.

This logic is implemented in:

- `detections/sigma/win_task_powerShell_registry_loader.yml`

Dataset validation produced two matching Security 4688 events, one for each task-launched PowerShell PID.

## Recommended multi-event correlation

The following correlation provides higher confidence than any single event:

```text
4698 or TaskScheduler 106
  → same TaskName
TaskScheduler 129
  → task launch PID
4688 or Sysmon 1
  → same host and converted PID
child process or network event
  → same process ID within a short window
```

Useful correlation keys:

- host and event time;
- task name and task path;
- creator account and Logon ID;
- Task Scheduler launch PID;
- process ID conversion between decimal and hexadecimal representations;
- process GUID where Sysmon provides it;
- parent image and parent PID;
- destination address and port.

Recommended window: five minutes for the creation sequence and 15 minutes for post-logon execution. Extend the execution window for tasks with delayed or periodic triggers.

## Task configuration analytics

Normalise Security 4698/4702 task XML into dedicated fields:

- `TaskName`;
- `Author`;
- `UserId`;
- `RunLevel`;
- trigger type;
- action command;
- action arguments;
- hidden setting;
- working directory.

Score combinations rather than individual strings:

| Feature | Suggested weight |
|---|---:|
| Run as `SYSTEM` | 2 |
| Logon or boot trigger | 2 |
| PowerShell action | 2 |
| Hidden window | 2 |
| Encoded command or Base64 decoder | 3 |
| Registry-backed script retrieval | 3 |
| `IEX` or `Invoke-Expression` | 3 |
| User-writable or temporary path | 2 |
| Unrecognised task path/name | 1 |
| No approved change/deployment match | 2 |

A score-based approach allows routine management tasks to be suppressed through approved task baselines without weakening detection of risky combinations.

## False-positive controls

Expected legitimate sources include:

- Windows Update and built-in Microsoft maintenance tasks;
- endpoint management and software-deployment agents;
- backup, monitoring, and security products;
- approved administrators deploying logon-time remediation;
- vulnerability-management or red-team exercises.

Tune using:

- exact task path and publisher baseline;
- signed and approved action binary;
- known deployment parent process;
- change-ticket or maintenance-window correlation;
- expected service account and originating management host;
- known command-line hash, not a broad PowerShell allowlist.

Do not suppress all tasks running as `SYSTEM` or all PowerShell task actions. Those controls would remove the most important context in this scenario.

## Detection gaps identified

### Task XML parsing

The working `task-definitions.tsv` export returned unresolved configuration fields even though Security 4698 recorded task content. Without XML extraction, the SIEM may ingest the event but fail to expose the properties required for reliable analytics.

Recommended fix:

1. Preserve the raw 4698 `TaskContent` or full message.
2. Parse the default XML namespace correctly.
3. Unit-test extraction against logon, boot, time, and event triggers.
4. Retain both raw and normalised representations.
5. Alert when parsing fails for a task-creation event.

### PowerShell content

Process telemetry confirms PowerShell execution, but usable script-block content was not required to establish the final chain. In production, enable and centralise Script Block Logging where policy and privacy requirements permit, then monitor Event ID `4104` for registry-backed decoders and dynamic code execution.

### File and signer context

No relevant payload hash or signer was available. Enrich process events with file creation, module load, signature, reputation, and code-integrity telemetry where possible.

### Network application context

Windows Filtering Platform events established destination IP, port, protocol, and process ID but not HTTP method, URI, headers, or payload. Proxy, firewall, DNS, EDR network, or packet telemetry would improve application-level assessment.

### Change-management context

The dataset has no change or deployment records. In production, join scheduled-task detections to CMDB, endpoint-management, software-deployment, and ticketing sources before closing an alert as authorised.

## Validation summary

Detailed validation results are stored in `evidence/processed/detection-validation.csv`.

| Rule | Raw matches | Unique activities | Result |
|---|---:|---:|---|
| Suspicious `schtasks.exe` SYSTEM/ONLOGON PowerShell action | 2 | 1 | Expected match confirmed across Sysmon and Security |
| Task-launched PowerShell registry loader | 2 | 2 | Expected match confirmed for PIDs 620 and 636 |

Validation used the known investigation window and is a functional test, not a production precision or recall benchmark. Broader benign-task testing is required before deployment.

