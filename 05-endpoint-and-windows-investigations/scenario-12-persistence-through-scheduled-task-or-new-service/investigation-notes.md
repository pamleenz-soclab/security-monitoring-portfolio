# Investigation Notes

## Investigation objective

Determine whether the observed scheduled-task activity represents authorised administration or attacker persistence, and establish whether the task was only created or also executed.

## Working hypotheses

### H1 — Malicious scheduled-task persistence

An elevated session stores an encoded loader in the registry, creates a logon-triggered task that runs hidden PowerShell as `SYSTEM`, restarts the host, and uses the resulting task execution for follow-on activity.

Expected supporting evidence:

- correlated creator identity and session across registry and process events;
- task creation and registration events;
- `SYSTEM` run account and logon trigger in command line or task definition;
- post-logon task launch;
- task PID matching process and network telemetry;
- suspicious child-process or network behaviour.

Result: **Supported and confirmed within the simulation dataset.**

### H2 — Legitimate administrator automation

An administrator creates a task for approved maintenance, software deployment, or endpoint management.

Expected supporting evidence:

- recognised software or management-agent path;
- documented change or deployment record;
- transparent script path and signed binary;
- task name and configuration consistent with enterprise baseline;
- no encoded registry loader or unexplained outbound communication.

Result: **Not supported by the available telemetry.** Change and deployment records are not available, so real-world authorisation remains unable to confirm rather than disproved.

### H3 — Task created but never executed

The persistence object exists but produces no later process or network activity.

Result: **Rejected for `\MordorElevated`.** Task Scheduler 129, Security 4688, child-process, and network records confirm execution. This hypothesis remains inapplicable to future activity after the short evidence window.

## Correlation method

### Creator session

The registry write, `schtasks.exe`, and `shutdown.exe` events share:

- host label `LAB-WKS-05`;
- account label `LAB\user-a`;
- creator Logon ID `0xa1d79` for process events;
- parent PowerShell context;
- a narrow time sequence between `17:58:17` and `17:59:04`.

No Security 4624 or 4672 event for Logon ID `0xa1d79` appears in the available window. The session can be attributed to the account recorded in the process and task events, but its original source and logon type cannot be reconstructed.

### Task creation

At `17:58:17`:

- Sysmon 1 record `3114432` and Security 4688 record `755555` describe the same `schtasks.exe` creation process.
- Security 4698 record `755562` records `\MordorElevated` creation by the same account and Logon ID.
- Task Scheduler 106 record `7153` records registration of the same task.
- Sysmon 12/13 records `3114460–3114463` record creation and value-setting under the task's TaskCache registry path.

The process command line confirms the configuration: forced creation, `SYSTEM` run account, `ONLOGON` schedule, task name, and hidden PowerShell action. The task XML normalisation output did not extract these values, so the report does not claim XML-based validation.

### Reboot and trigger

The creator session launched `shutdown.exe /r` at `17:59:04`. The following records confirm a completed restart rather than a mere request:

- System 6006 record `1279`: Event Log service stopped;
- System 109 record `1291`: kernel initiated shutdown;
- System 13 record `1292`: operating system shutting down;
- System 12 record `1293`: operating system started;
- Security 4608 record `760413`: Windows auditing subsystem started.

Security 4624 records `771728` and `771730` then record remote interactive Logon Type 10 activity for the same account label. Record `771728` uses Logon ID `0x10a7df`, and Security 4672 record `771732` assigns special privileges to that same logon session.

These are post-reboot sessions and must not be merged with creator Logon ID `0xa1d79`.

### Task execution and PID conversion

At `18:01:15`:

- Task Scheduler 129 record `7293` launches `\MordorElevated` as PowerShell PID `620`.
- Security 4688 record `772054` creates PowerShell process ID `0x26c`.
- `0x26c` converted to decimal equals `620`.
- The 4688 event uses local `SYSTEM` Logon ID `0x3e7` and system integrity SID `S-1-16-16384`.

A parallel task execution is also present:

- `\MordorElevatedTask` → Task Scheduler PID `636`;
- Security 4688 process ID `0x27c` → decimal `636`.

The second task's creation is not observed; only its execution is confirmed.

### Child process and network activity

At `18:01:39`, each PowerShell process launches a separate `csc.exe` child:

| PowerShell | 4688 record | Child PID | Child record |
|---:|---:|---:|---:|
| `620` / `0x26c` | `772054` | `6780` / `0x1a7c` | `773273` |
| `636` / `0x27c` | `772055` | `5360` / `0x14f0` | `773272` |

At `18:01:41`, Windows Filtering Platform events connect the original PowerShell PIDs to the deactivated lab endpoint:

| PID | Local port | Destination | Records |
|---:|---:|---|---|
| `620` | `49795` | `10[.]10[.]10[.]5:80/TCP` | `773420–773421` |
| `636` | `49794` | `10[.]10[.]10[.]5:80/TCP` | `773418–773419` |

The evidence confirms TCP communication to port `80`. It does not expose application-layer payloads, so the protocol is not labelled as confirmed HTTP.

## Alternative-explanation review

| Alternative | Evidence review | Decision |
|---|---|---|
| Windows built-in task | Other Microsoft tasks appear in the dataset, but the investigated task has a custom name, hidden PowerShell registry loader, and follow-on network activity | Not supported |
| Software installer | No installer parent, deployment metadata, signed payload, or change record is available | Not available / unsupported |
| Security test or red-team action | Dataset attribution confirms an Empire simulation | Confirmed as dataset context |
| Service-based persistence | One 7045 event lacks usable service fields and cannot be correlated to the task chain | Unable to confirm; excluded |

## Analyst decision log

1. Chose the scheduled-task route because evidence supported creation and execution correlation.
2. Did not use the task name alone as proof of maliciousness.
3. Did not copy or decode the complete encoded PowerShell payload.
4. Treated two telemetry records for the same `schtasks.exe` process as cross-source corroboration, not two creation actions.
5. Kept `\MordorElevatedTask` separate because its creation record is absent.
6. Did not treat the domain controller's authentication events as persistence execution on that host.
7. Did not claim HTTP based only on TCP destination port `80`.
8. Did not include Event ID `7045` in the confirmed chain because service configuration was unavailable.

