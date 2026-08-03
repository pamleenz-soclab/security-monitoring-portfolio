# Dataset Decision Record

## Scenario

Scenario 12 — Persistence Through Scheduled Task or New Service

## Decision

The primary investigation route is Windows Scheduled Task persistence, initially mapped to MITRE ATT&CK T1053.005.

The selected dataset is OTRF Security-Datasets:

- Dataset: Empire Elevated Scheduled Tasks
- Archive: empire_schtasks_creation_execution_elevated_user.zip
- Source: https://github.com/OTRF/Security-Datasets
- Dataset page: https://securitydatasets.com/notebooks/atomic/windows/persistence/SDWIN-200921175806.html
- Data type: simulated adversary-emulation lab telemetry
- Analysis mode: offline log analysis only

## Selection Rationale

The selected dataset provides stronger evidence correlation than the alternatives reviewed. It includes:

- Security Event ID 4698 scheduled-task creation events;
- complete TaskContent XML;
- Task Scheduler Operational events;
- Windows 4688 and Sysmon Event ID 1 process telemetry;
- PowerShell telemetry;
- Sysmon and Windows Filtering Platform network telemetry;
- both suspicious activity and normal scheduled-task background activity.

This permits investigation of task creation, configuration, execution, process lineage, privilege context, and potential network activity.

## Alternatives Considered

| Candidate | Strength | Primary limitation | Decision |
|---|---|---|---|
| OTRF Empire Elevated Scheduled Tasks | Multi-channel creation and execution evidence | Simulated data and incomplete file-reputation context | Selected |
| OTRF Empire Userland Scheduled Tasks | Task creation and XML evidence | Trigger falls outside the collection window | Not selected |
| OTRF Covenant SharpSC Create | 4697, 7045 and service configuration evidence | Service execution not observed; remote-service lateral-movement context | Deferred |
| Splunk taskschedule | Sysmon process and registry telemetry | No 4698, task XML or Task Scheduler Operational evidence | Not selected |
| Splunk single-event samples | Useful for rule validation | Insufficient for full incident reconstruction | Not selected |

## Integrity Baseline

- ZIP size: 4,241,110 bytes
- ZIP SHA-256: 74662dc5c52f4ac2fc9dcb336bae7fb4e101217169c65adf5784b03015501d3b
- Extracted JSON size: 95,587,556 bytes
- JSON records: 59,399
- JSON validation: passed
- Executable content in archive: not observed

## Licensing and Publication Boundary

The repository LICENSE file states MIT, while repository documentation contains a GPL-3.0 reference. Because of this inconsistency, the portfolio will use a conservative publication boundary:

- raw ZIP and JSON files will not be committed;
- only minimal, attributed and sanitised derived evidence will be published;
- full encoded commands and inactive external indicators will not be reproduced unnecessarily;
- the original dataset source will be cited.

## Known Evidence Limitations

The dataset does not provide real organisational change tickets, asset ownership, deployment records, user interviews, EDR reputation results or independent authorisation records.

Whether the actions were authorised in a real enterprise is therefore unable to be confirmed.

## Current Conclusion Boundary

Dataset suitability is confirmed. No final maliciousness conclusion has been made at this stage.
