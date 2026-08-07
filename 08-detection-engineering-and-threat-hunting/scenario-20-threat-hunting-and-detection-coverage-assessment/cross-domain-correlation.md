# Cross-Domain Correlation

## HC-01 — identity sequence to cloud activity

Primary pivots:

```text
User
→ MFA failure/denial/timeout sequence
→ successful sign-in
→ SessionId
→ Office / cloud activity
```

Precision review showed that the existing Scenario 17 follow-on KQL already correlates same-user, same-session operations within two hours for selected high-risk operations.

## HC-03 — process to file/network

Primary pivots:

```text
PowerShell ProcessGuid
→ parent/child process
→ file activity
→ outbound network activity
```

This is the confirmed detection-gap example because the telemetry is present while no dedicated Scenario 10 rule artifact was inventoried.

## HC-05 — Windows authentication to SMB remote service

Primary pivots:

```text
Source IP / workstation
→ account
→ TargetLogonId / SubjectLogonId
→ TCP/445
→ IPC$\svcctl
→ service installation
→ remote service process
```

The core correlation already exists in Scenario 13's Sentinel and Splunk examples.

## HC-10 — service-principal credential to API use

Primary pivots:

```text
AppId / ServicePrincipalId
→ credential key
→ service-principal sign-in
→ token / request identifiers
→ API / resource activity
```

The hunt extends beyond R19-04's credential-to-sign-in terminal event while preserving the limitation that a specific permission claim cannot be attributed to every API request.
