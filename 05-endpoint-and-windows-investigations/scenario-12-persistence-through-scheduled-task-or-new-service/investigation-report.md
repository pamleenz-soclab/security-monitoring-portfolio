# Investigation Report

## 1. Case overview

This investigation assessed Windows persistence activity in the OTRF **Empire Elevated Scheduled Tasks** dataset. The collection contains 59,399 events from three simulated hosts over a 4-minute-and-21-second window.

The primary question was whether a scheduled task represented ordinary administration or adversary persistence, and whether telemetry proved only creation or also subsequent execution.

## 2. Final assessment

> **True Positive — confirmed simulated malicious scheduled-task persistence.**

On `LAB-WKS-05`, a high-integrity PowerShell session associated with `LAB\user-a` wrote encoded content to a registry value and created `\MordorElevated`. The observed `schtasks.exe` command configured the task to run at logon as `SYSTEM` and launch hidden PowerShell that read, decoded, and executed the registry-backed content. After a confirmed reboot and remote interactive logon, Windows recorded task launch, `SYSTEM` PowerShell execution, dynamic C# compilation, and a TCP connection to a deactivated lab controller address.

The OTRF metadata identifies the activity as an Empire simulation. The event evidence independently validates the behaviour chain; it does not independently establish production authorisation or the operator's intent outside that simulation context.

## 3. Evidence sources

| Data source | Relevant events | Contribution |
|---|---|---|
| Sysmon Operational | 1, 12, 13 | Process creation, registry write, TaskCache changes |
| Windows Security | 4624, 4672, 4688, 4698, 5156, 5158 | Identity, privilege, process, task, and network context |
| Task Scheduler Operational | 106, 129 | Task registration and task-to-PID mapping |
| Windows System | 12, 13, 109, 6006 | Reboot validation |
| PowerShell channels | Candidate host and operational events | Supplemental context; no complete decoded payload published |

## 4. Detailed timeline

### 4.1 Payload storage and task creation

At `17:58:17`, Sysmon 13 record `3114429` recorded PowerShell setting `HKLM\SOFTWARE\Microsoft\Network\debug`. The registry data was present in the source event, but its complete encoded content is excluded from publication.

At the same second, Sysmon 1 record `3114432` and Security 4688 record `755555` recorded the same `schtasks.exe` process. The significant command structure was:

```text
schtasks.exe /Create /F /RU system /SC ONLOGON
  /TN MordorElevated
  /TR "powershell.exe -NonI -W hidden -c [registry-backed loader redacted]"
```

Parameter interpretation:

| Parameter | Meaning | Investigative significance |
|---|---|---|
| `/Create` | Create a scheduled task | Establishes the persistence-object operation |
| `/F` | Force replacement if the name already exists | Allows silent overwrite of an existing task |
| `/RU system` | Run as local `SYSTEM` | Provides maximum local task execution privilege |
| `/SC ONLOGON` | Trigger at user logon | Establishes a persistence trigger |
| `/TN MordorElevated` | Set task name | Links command line to later task events |
| `/TR` | Define the task action | Launches hidden PowerShell and a registry-backed loader |
| `-NonI` | Non-interactive PowerShell | Suitable for unattended execution |
| `-W hidden` | Hide the PowerShell window | Reduces user visibility |

Security 4698 record `755562` recorded the creation of `\MordorElevated` by the same account label and creator Logon ID `0xa1d79`. Task Scheduler 106 record `7153` confirmed registration of the same task. Sysmon 12/13 records `3114460–3114463` recorded the corresponding TaskCache tree and values.

This combination confirms both the creator process and successful persistence-object creation.

### 4.2 Reboot validation

At `17:59:04`, Sysmon 1 record `3120221` and Security 4688 record `759551` recorded `shutdown.exe /r` from the same creator account and Logon ID.

The request resulted in an actual restart:

| Time | Source | Event | Record | Meaning |
|---|---|---:|---:|---|
| 17:59:36 | System | 6006 | 1279 | Event Log service stopped |
| 17:59:41 | System | 109 | 1291 | Kernel initiated shutdown |
| 17:59:44 | System | 13 | 1292 | Operating system shutting down |
| 17:59:46 | System | 12 | 1293 | Operating system started |
| 18:00:10 | Security | 4608 | 760413 | Windows auditing subsystem started |

The reboot is therefore **Confirmed**, not inferred from the command alone.

### 4.3 Post-reboot logon

At `18:01:12`, Security 4624 records `771728` and `771730` recorded remote interactive Logon Type 10 activity for `LAB\user-a`. Record `771728` created Logon ID `0x10a7df` with an elevated token, and Security 4672 record `771732` assigned special privileges to that same ID.

These are new post-reboot sessions. They support the timing of the `ONLOGON` trigger but must not be conflated with creator Logon ID `0xa1d79`.

### 4.4 Task launch and system-level execution

Three seconds after the remote interactive logon, Task Scheduler Event ID `129` recorded two task launches:

| Task | Event record | Scheduler PID | Related 4688 | 4688 PID | Integrity |
|---|---:|---:|---:|---:|---|
| `\MordorElevated` | `7293` | `620` | `772054` | `0x26c` | System |
| `\MordorElevatedTask` | `7290` | `636` | `772055` | `0x27c` | System |

Hexadecimal-to-decimal conversion establishes the link:

- `0x26c` = `620`;
- `0x27c` = `636`.

Both 4688 events recorded the local machine account, Logon ID `0x3e7`, parent `svchost.exe`, and mandatory integrity SID `S-1-16-16384`. The command line matched the hidden PowerShell registry loader used in the task action.

Creation of `\MordorElevatedTask` was not observed in this collection. Its execution and follow-on behaviour are confirmed, but its creator and creation time are not.

### 4.5 Dynamic compilation

At `18:01:39`, the task-launched PowerShell processes created separate instances of the .NET C# compiler:

| Parent PowerShell | `csc.exe` PID | 4688 record | Evidence |
|---:|---:|---:|---|
| `620` | `6780` | `773273` | Compiler command references a temporary `.cmdline` response file |
| `636` | `5360` | `773272` | Compiler command references a separate temporary `.cmdline` response file |

`csc.exe` can be legitimate. Here it is significant because it is a direct child of two hidden, `SYSTEM` PowerShell registry loaders within the persistence execution chain. The events confirm dynamic compilation; they do not expose the compiled source code in the published evidence.

### 4.6 Network communication

At `18:01:41`, Windows Filtering Platform records tied the two PowerShell PIDs to TCP connections:

| PID | Local endpoint | Destination | Event records |
|---:|---|---|---|
| `620` | `LAB-WKS-05:49795` | `10[.]10[.]10[.]5:80` | `773420`, `773421` |
| `636` | `LAB-WKS-05:49794` | `10[.]10[.]10[.]5:80` | `773418`, `773419` |

The destination is a private lab address and is described only as the dataset's simulated controller endpoint. Event ID `5156` confirms an allowed TCP connection to port `80`; without packet or proxy telemetry, application-layer HTTP cannot be independently confirmed.

## 5. Attribution and scope

### Confirmed scope

- One primary workstation contains the complete observed creation and execution chain.
- `LAB\user-a` is recorded as the creator of `\MordorElevated`.
- The task executes in the local `SYSTEM` context.
- A second related task executes on the same workstation but lacks an observed creation event.

### Scope not established

- Scheduled-task persistence on the other workstation or domain controller;
- lateral movement caused by the scheduled task;
- payload file creation or an on-disk binary;
- repeated task execution outside the short collection window;
- production authorisation, ticket ownership, or business impact.

## 6. Evidence-status assessment

| Finding | Status | Basis |
|---|---|---|
| Registry-backed content was written | Confirmed | Sysmon 13 record `3114429` |
| `\MordorElevated` was created and registered | Confirmed | 4698 record `755562`; 106 record `7153` |
| Creator process was elevated | Confirmed | High integrity in process telemetry |
| Task was configured for `SYSTEM` and `ONLOGON` | Confirmed | `schtasks.exe` command line, later system execution, and post-logon timing |
| The host rebooted | Confirmed | Shutdown, startup, and audit-start events |
| The task executed | Confirmed | 129 → decimal PID → 4688 correlation |
| Dynamic compilation occurred | Confirmed | `csc.exe` child-process events |
| TCP communication to `10[.]10[.]10[.]5:80` occurred | Confirmed | 5156 records tied to PowerShell PIDs |
| Communication used HTTP application data | Unable to confirm | No packet, proxy, or application-layer evidence |
| `\MordorElevatedTask` was created by the same account | Unable to confirm | Creation not observed |
| Creator session originated from a specific source | Unable to confirm | 4624/4672 for `0xa1d79` not observed |
| A service was installed as part of the chain | Unable to confirm | 7045 lacks usable details |
| Change approval existed | Not available | No ticketing or deployment source |
| Parsed task XML confirmed all settings | Detection gap | Task configuration fields were not extracted by the normalisation query |

## 7. MITRE ATT&CK mapping

| Technique | Mapping | Evidence |
|---|---|---|
| `T1053.005` | Scheduled Task/Job: Scheduled Task | Task creation, registration, logon trigger, and execution |
| `T1059.001` | Command and Scripting Interpreter: PowerShell | Hidden PowerShell creator and task action |
| `T1112` | Modify Registry | Registry value used by the loader and TaskCache changes |
| `T1027` | Obfuscated/Compressed Files and Information | Base64 decoding is explicitly present in the loader |

Valid-account use and application-layer web-protocol mappings are intentionally excluded because the telemetry does not prove account compromise or HTTP content.

## 8. Conclusion

The case exceeds a creation-only finding. Multiple independent event sources form a continuous chain from registry staging and task creation through reboot, logon-triggered `SYSTEM` execution, child compilation, and network communication.

The appropriate portfolio classification is:

> **Confirmed malicious behaviour within an attributed Empire simulation dataset; real-world authorisation cannot be independently assessed.**

