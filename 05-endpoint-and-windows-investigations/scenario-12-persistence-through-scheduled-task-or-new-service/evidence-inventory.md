# Evidence Inventory

## Raw Evidence

| Evidence | Location | Size | Handling |
|---|---|---:|---|
| Original ZIP archive | evidence/raw/otrf-empire-elevated-scheduled-task/empire_schtasks_creation_execution_elevated_user.zip | 4,241,110 bytes | Local only, Git ignored, read-only |
| Extracted JSON Lines log | evidence/raw/otrf-empire-elevated-scheduled-task/empire_schtasks_creation_execution_elevated_user_2020-09-21175806.json | 95,587,556 bytes; 59,399 records | Local only, Git ignored, read-only |
| Raw directory placeholder | evidence/raw/.gitkeep | Not applicable | Intended for Git |

## Archive Integrity

- ZIP SHA-256: 74662dc5c52f4ac2fc9dcb336bae7fb4e101217169c65adf5784b03015501d3b
- ZIP integrity test: passed
- JSON parsing validation: passed
- Archive executable content: not observed

## Channel Inventory

| Channel | Records |
|---|---:|
| Microsoft-Windows-Sysmon/Operational | 35,889 |
| security | 19,431 |
| Security | 2,852 |
| Windows PowerShell | 545 |
| Microsoft-Windows-PowerShell/Operational | 466 |
| System | 90 |
| Microsoft-Windows-WMI-Activity/Operational | 64 |
| Microsoft-Windows-TaskScheduler/Operational | 33 |

Channel names are preserved exactly as recorded. The values `security` and `Security` will not be merged silently during evidence extraction.

## Initial Key Event Inventory

| Channel | Event ID | Count | Candidate relevance |
|---|---:|---:|---|
| security | 4698 | 3 | Scheduled task created |
| security | 4702 | 10 | Scheduled task updated |
| Task Scheduler Operational | 106 | 3 | Task registration |
| Task Scheduler Operational | 129 | 28 | Task process launch |
| Task Scheduler Operational | 141 | 2 | Task deletion |
| security | 4688 | 335 | Process creation |
| Security | 4688 | 4 | Process creation |
| Sysmon Operational | 1 | 216 | Process creation |
| Sysmon Operational | 3 | 38 | Network connection |
| security/Security | 5156 and 5158 | 2,403 | Network connection and bind telemetry |

These counts are inventory observations only. They do not establish that every listed event belongs to the suspected scheduled task.

## Planned Derived Evidence

The investigation will derive:

- scheduled-task lifecycle timeline;
- task-definition summary;
- task-creation process evidence;
- execution-process and PID correlation;
- login and privilege context;
- relevant network activity;
- sanitised final evidence timeline.

Temporary unsanitised query results will remain under evidence/working and will not be committed.
