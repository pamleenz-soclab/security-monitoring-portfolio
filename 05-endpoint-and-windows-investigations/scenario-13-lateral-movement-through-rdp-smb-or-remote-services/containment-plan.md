# Containment and Recovery Plan

This operational sequence complements `recommended-actions.md`.

## Priority 0 — preserve and coordinate

- Open a high-severity incident and assign an incident commander.
- Record current UTC time, active users, isolation actions and owners.
- Preserve memory/EDR triage packages before reboot where operationally possible.
- Export Security, System, Sysmon and PowerShell logs from both endpoints and relevant domain-controller events.
- Validate whether a change, deployment or approved administrator action exists.

## Priority 1 — contain active access

1. Isolate `WORKSTATION5` and `WORKSTATION6` while retaining management visibility.
2. Disable or reset `THESHIRE\pgustavo` according to identity policy.
3. Force supported session invalidation/logoff and purge Kerberos tickets where applicable.
4. Block the corresponding confirmed callback destination and URI in a production incident. `10.10.10.5` is the private endpoint used by this lab simulation.
5. Restrict east-west TCP/445 between workstation segments except approved management paths.
6. Block or alert on remote Service Control Manager activity from ordinary user workstations.

## Priority 2 — scope

- Search all endpoints for service `PGUJLOAKFQFVOMHGFQPX` and other transient high-entropy service names.
- Hunt for Type 3 NTLM logons by `pgustavo`, especially from unapproved administration sources.
- Correlate 5145 `svcctl` with 4697/7045 and `services.exe` children within two minutes.
- Search for `%COMSPEC% /C`, `-enc`, `-w 1`, `amsiInitFailed`, `DownloadData` and `IEX`.
- Search for source ProcessGuid `{b34bc01c-f6f9-5f66-b410-000000000400}` and target ProcessGuid `{d273d0f0-fd6c-5f66-7605-000000000800}` where raw EDR retains them.
- Review all production-equivalent connections matching the identified destination/URI pattern.
- Determine where `pgustavo` had privileged rights and where the account logged on before and after the event.

## Priority 3 — eradicate and recover

- Reimage both endpoints if production evidence confirms an active agent or if system integrity cannot be established.
- Remove unauthorized services and registry keys only after forensic preservation.
- Rotate local administrator, service and cached privileged credentials exposed to either endpoint.
- Validate endpoint controls, Sysmon configuration, PowerShell logging and EDR health before reconnecting.
- Reconnect one host at a time under increased telemetry and confirm no callback or service recreation.

## Long-term controls

- Prefer Kerberos and reduce/monitor NTLM where compatibility permits.
- Use privileged access workstations and deny administrative SMB from normal user workstations.
- Limit SMB/RPC management with Windows Firewall to defined sources.
- Enforce unique local administrator passwords with Windows LAPS.
- Baseline approved deployment tools, service patterns, accounts and management subnets.
- Alert on temporary service creation followed by `services.exe` spawning shell interpreters.

## Closure criteria

- No further unauthorized callback or lateral SMB activity during enhanced monitoring.
- Compromised endpoints rebuilt or validated by the incident-response standard.
- Account and exposed credentials rotated, with privileged access reviewed.
- Enterprise-wide hunt returns no unresolved confirmed target hosts.
- Detection rules deployed, tuned against approved administration and tested with an authorized simulation.
