# Recommended Actions

These actions describe how to respond to an equivalent production incident. They were not executed against the historical lab dataset.

## 1. Containment

### Endpoint

- Isolate the affected host through EDR or network controls while preserving management access for responders.
- Prevent both confirmed task-launched PowerShell processes from continuing.
- Block creation of new scheduled tasks from the implicated account or host until scope is known.
- Apply temporary egress controls for the confirmed destination and any related infrastructure found during scoping.

### Identity

- Disable or constrain the implicated account after checking for safety-critical dependencies.
- Revoke active sessions and refresh tokens where applicable.
- Reset credentials from a known-clean administrative workstation.
- Review group memberships, delegated rights, remote-logon privileges, and recent account changes.

## 2. Evidence preservation

Before deleting persistence objects:

- export task XML for `\MordorElevated` and `\MordorElevatedTask`;
- capture `schtasks /Query /TN <task> /XML` output through an approved response process;
- collect the task files and TaskCache registry keys;
- export `HKLM\SOFTWARE\Microsoft\Network\debug` without executing or decoding it on the affected host;
- acquire volatile process, network, and memory evidence where proportionate;
- preserve Security, Sysmon, Task Scheduler, PowerShell, System, EDR, DNS, proxy, and firewall logs;
- record timestamps, responder actions, and evidence hashes.

## 3. Eradication

- Delete confirmed malicious task objects after evidence capture.
- Remove associated TaskCache remnants only through supported Windows procedures or a validated forensic remediation plan.
- Remove the malicious registry value after acquisition.
- Delete related scripts, temporary compiler artifacts, and payload files only after their hashes and metadata are preserved.
- Repair any audit-policy, PowerShell-logging, or endpoint-control changes made by the operator.
- Reimage the system when integrity cannot be established or when in-memory activity cannot be contained reliably.

## 4. Scope expansion

Hunt across the enterprise for:

- the two task names and near-name variants;
- `schtasks.exe` commands combining `/Create`, `/RU SYSTEM`, `/SC ONLOGON`, and a PowerShell `/TR` action;
- PowerShell retrieving data from uncommon `HKLM` values and using `FromBase64String` plus `IEX`;
- Task Scheduler 129 followed by `SYSTEM` PowerShell;
- PowerShell spawning `csc.exe` from temporary response files;
- network activity from the same PIDs or destination pattern;
- the implicated account creating other tasks, services, WMI subscriptions, run keys, or remote sessions;
- equivalent activity from the creator host or remote source in the same time range.

Search back far enough to locate the missing creation of `\MordorElevatedTask`; the four-minute collection cannot establish when it first appeared.

## 5. Recovery

- Reconnect the host only after task, registry, process, identity, and network indicators are cleared.
- Confirm endpoint protection and logging agents are healthy and tamper protection is enabled.
- Validate that no unexpected scheduled task reappears after reboot and logon.
- Monitor the recovered account and host under heightened detection for an agreed period.
- Restore normal access gradually, documenting each decision.

## 6. Validation checklist

| Validation | Expected result |
|---|---|
| Query both task names | No unauthorised task remains |
| Inspect TaskCache and task files | No orphaned malicious entries |
| Inspect the registry loader location | Malicious value removed after preservation |
| Reboot and perform controlled logon | No hidden PowerShell task action starts |
| Review process telemetry | No matching registry-loader or compiler chain |
| Review network telemetry | No recurrence of related connections |
| Review account activity | No unexplained privileged or remote sessions |
| Re-run enterprise hunt | No additional affected hosts or accounts |

## 7. Preventive improvements

- Centralise Security 4698/4702 and Task Scheduler Operational logs.
- Parse task XML into searchable action, trigger, run-account, and run-level fields.
- Collect process command lines and preserve decimal/hexadecimal PID relationships.
- Enable appropriate PowerShell logging and protect its configuration.
- Correlate task creation with process, child-process, network, identity, and change-management telemetry.
- Restrict who can create `SYSTEM` tasks and review this privilege periodically.
- Baseline legitimate scheduled tasks by path, publisher, account, and deployment source.
- Test the supplied Sigma rules against representative benign enterprise task activity before production use.

## 8. Lessons for incident handling

- A task-creation event is not proof that the task executed; execution needs separate evidence.
- A `SYSTEM` task is not automatically malicious; the trigger, action, creator, and follow-on behaviour determine risk.
- Port `80` does not independently prove HTTP.
- Missing change records are not proof that no approval existed; they are an evidence limitation and governance gap.
- Raw task content must remain accessible even when normalised fields fail, otherwise a parsing issue becomes a detection blind spot.

