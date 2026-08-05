# Recommended Actions

## 1. Validate authorization before destructive action

- Check change tickets, software-deployment records, remote-support sessions and administrator activity for `WORKSTATION5 → WORKSTATION6` at the incident time.
- Confirm whether `THESHIRE\pgustavo` was expected to administer the target.
- Contact the account owner and target asset owner through an independent channel.
- Preserve the result as **Authorized**, **Unauthorized** or **Unable to confirm**; telemetry alone does not answer this question.

## 2. Immediate containment

1. Isolate `WORKSTATION5` and `WORKSTATION6` while retaining EDR management access where possible.
2. Disable or reset `THESHIRE\pgustavo` under the incident identity procedure.
3. Force supported session invalidation and user logoff; purge Kerberos tickets where applicable after credential reset.
4. Restrict east-west TCP/445 and remote SCM access to approved management sources.
5. In production, block the confirmed callback destination and URI. The address `10.10.10.5` in this scenario is a private lab endpoint, not public malicious infrastructure.

## 3. Evidence preservation

- Capture volatile process/memory and EDR triage artifacts before reboot where feasible.
- Export Security, System, Sysmon and PowerShell logs from both endpoints.
- Preserve relevant 4776/domain-controller evidence and network/proxy/firewall logs.
- Record isolation, credential and blocking actions with UTC timestamps and owners.

## 4. Credential and identity response

- Review privileged group membership and delegated rights for `THESHIRE\pgustavo`.
- Search for use of the account from other source hosts before and after the event.
- Rotate credentials exposed on either endpoint, including local administrator, service and cached privileged credentials, according to impact assessment.
- Review NTLM usage and migrate eligible management workflows to Kerberos or stronger alternatives.

## 5. Scope investigation

Hunt enterprise-wide for:

- Type 3 NTLM logons by `pgustavo` from unapproved sources;
- 5145 access to `IPC$\svcctl` followed by 4697/7045;
- service `PGUJLOAKFQFVOMHGFQPX` and other transient high-entropy service names;
- `%COMSPEC%`, nested `cmd.exe`, `-enc`, `-w 1`, `amsiInitFailed`, `DownloadData` and `IEX`;
- `services.exe` spawning command/script interpreters;
- the source and target ProcessGuids where EDR retains them;
- follow-on HTTP connections from newly created service-child processes;
- additional internal targets contacted by `WORKSTATION6`.

## 6. Eradication and recovery

- Reimage endpoints when evidence confirms an active in-memory agent or when integrity cannot be established.
- Remove unauthorized services and registry artifacts only after evidence preservation.
- Validate EDR, Sysmon, PowerShell logging and firewall controls before reconnecting.
- Reconnect systems in a controlled sequence with enhanced monitoring.

## 7. Detection and prevention improvements

- Collect 4624, 4672, 4697, 4776, 5140, 5145, 7045, Sysmon 1/3/12/13 and PowerShell 4104 centrally.
- Limit SMB/RPC administration to privileged access workstations and approved deployment systems.
- Use Windows LAPS for unique local administrator passwords.
- Alert on `IPC$\svcctl` followed by service creation and `services.exe` child interpreters.
- Retain false-positive tuning for approved deployment, EDR response, backup, vulnerability-scanning and remote-support activity.

## 8. Closure criteria

- No further unauthorized SMB/SCM or callback activity during enhanced monitoring.
- Source and target rebuilt or validated according to the incident-response standard.
- Account and exposed credentials rotated; privileged access reviewed.
- Scope hunt finds no additional confirmed targets, or all additional targets are remediated.
- Detection rules are deployed, tuned and validated with an authorized simulation.
