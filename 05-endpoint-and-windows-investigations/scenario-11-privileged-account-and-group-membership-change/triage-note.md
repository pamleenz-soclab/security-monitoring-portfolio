# Triage Note

## Alert summary

| Field | Value |
| --- | --- |
| Alert | New account added to privileged Administrators group |
| Detection time | 2020-10-09 10:41:26 (source time; UTC inferred) |
| Host | `win-dc-7216619.attackrange.local` |
| Actor | `ATTACKRANGE\Administrator` |
| Target | `ATTACKRANGE\T1136.001_Admin` |
| Group | `BUILTIN\Administrators` |
| Primary audit event | Windows Security 4732, Record 228843 |
| Initial severity | **High** — privileged membership added on a domain controller |
| Final severity | **Informational / closed** — controlled simulation, cleanup confirmed |
| Detection disposition | **True Positive** |
| Business classification | **Legitimate Authorised Change / Controlled Security Test** |

## Initial triage assessment

Event 4732 confirms that a member was added to a security-enabled local/domain-local group. The event is security-relevant because the target group is Administrators and the host is a domain controller. This establishes the technical fact of a privilege change, but it does not by itself establish malicious intent.

The first required pivots were:

- identify the Subject that performed the change;
- resolve the target member and target group;
- link the Subject Logon ID to the actor session and process chain;
- find account creation and lifecycle events;
- check whether the target used the new access;
- validate authorisation and cleanup independently.

## High-confidence findings

- `ATTACKRANGE\Administrator` created and modified the target under Logon ID `0x79779`.
- Events 4720, 4722, 4724, and 4738 confirm creation, enablement, password setting, and account-control changes.
- Event 4732 confirms addition to `BUILTIN\Administrators`.
- Sysmon confirms `cmd.exe -> net.exe -> net1.exe` commands for creation and group addition.
- The decoded parent command identifies `Invoke-AtomicTest "T1136.001"`.
- A separate cleanup session, `0x7FE66`, deleted the target with `net user /del`; Event 4726 confirms deletion.

## Post-change activity check

| Check | Result |
| --- | --- |
| Target successful or failed logon, 4624/4625 | Not observed |
| Target explicit credential use, 4648 | Not observed |
| Target special-privilege session, 4672 | Not observed |
| Sysmon process executed as target | Not observed |
| Explicit group-member removal, 4733 | Not observed |
| Account deletion, 4726 | Confirmed |
| Ticket, approver, or approved window | Not available |

The observed 4672 events belong to the Administrator actor sessions. They must not be attributed to the newly created account.

## Triage decision

Close as a **true-positive detection of an authorised controlled security test**. The account and group changes occurred exactly as detected, so this is not a false positive. The business intent is supported by the official dataset metadata and the Atomic execution and cleanup commands.

No containment is required in the lab. In production, the same detection should remain High until an approved ticket, authorised actor, expected target, exact group, and valid change window are verified. If authorisation cannot be established promptly, escalate as a suspected unauthorised privilege change and begin reversible containment.

## Evidence limitations

- Ticket and approval evidence: **Not available** because the dataset does not contain those systems.
- Actor source IP: **Not observed** because the 4624 field is present but recorded as `-`.
- Target post-change use: **Not observed** after searching the telemetry types that could show it.
- Cross-host activity: **Not available** because coverage is limited to the selected host and sources.
