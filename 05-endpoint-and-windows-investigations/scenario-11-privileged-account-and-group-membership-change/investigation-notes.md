# Concentrated Investigation Notes

## Preliminary outcome

The evidence confirms a real privileged-account change inside a controlled Atomic Red Team lab:

```text
ATTACKRANGE\Administrator / Logon ID 0x79779
  -> launches Atomic test T1136.001
  -> creates and enables ATTACKRANGE\T1136.001_Admin
  -> sets its password and changes UAC attributes
  -> adds it to BUILTIN\Administrators
  -> no target-account logon or administrative process is observed
  -> cleanup session 0x7FE66 deletes the target about three seconds later
```

**Detection disposition:** True Positive — account creation and privileged membership change occurred.

**Business/intent classification:** Authorized controlled security test, based on the official Attack Range dataset metadata and the decoded `Invoke-AtomicTest T1136.001` process evidence. A production change ticket, approver, and approved window are **Not available** in the dataset.

**Production analogue:** If the same events appeared on a production domain controller without an approved change record, the correct interim classification would be **Suspicious change / possible unauthorized privilege escalation**, not automatically malicious. Immediate authorization validation and containment readiness would be required.

## Confirmed timeline

| Time | Evidence | Finding |
| --- | --- | --- |
| 10:41:23 | Security 4624, Record 228808 | `ATTACKRANGE\Administrator` receives network Logon ID `0x79779` on the DC; source IP is `-` |
| 10:41:23 | Security 4672, Record 228809 | Sensitive privileges are assigned to actor session `0x79779` |
| 10:41:26.060Z | Sysmon 1, Record 4277 | High-integrity `cmd.exe` is launched by the Atomic test under the same user and Logon ID |
| 10:41:26.066Z | Sysmon 1, Record 4291 | `net user /add` requests creation of `T1136.001_Admin`; lab password is redacted in processed evidence |
| 10:41:26 | Security 4720, Record 228839 | Target account created; initial UAC `0x15` means disabled normal account with password-not-required flag |
| 10:41:26 | Security 4722, Record 228840 | Target account enabled |
| 10:41:26 | Security 4724, Record 228841 | Password reset recorded with Audit Success |
| 10:41:26 | Security 4738, Record 228842 | Password Last Set updated and UAC changes `0x15 -> 0x10`, consistent with enabled/password-required state |
| 10:41:26.106Z | Sysmon 1, Record 4317 | `net localgroup administrators ... /add` launched by the same actor session |
| 10:41:26.111Z | Sysmon 1, Record 4330 | `net1.exe` executes the group-add operation |
| 10:41:26 | Security 4732, Record 228843 | Target principal added to `BUILTIN\Administrators` by actor session `0x79779` |
| 10:41:26 | Security 4735, Record 228844 | Supplemental Administrators-group change event |
| 10:41:26 | Security 4624/4672, Records 228865/228866 | Administrator cleanup session `0x7FE66` is established and receives sensitive privileges |
| 10:41:29.003Z | Sysmon 1, Record 4600 | Atomic cleanup launches `cmd.exe` under cleanup session `0x7FE66` |
| 10:41:29.009–.014Z | Sysmon 1, Records 4614/4627 | `net.exe`/`net1.exe` execute `net user /del T1136.001_Admin` |
| 10:41:29 | Security 4726, Record 228888 | Target account deletion confirmed |

Windows Security text only retains whole seconds. Sysmon provides sub-second UTC values. Within the same Security channel and computer, RecordNumber/EventRecordID orders the same-second lifecycle events; it is not used as a global ordering key across Sysmon and Security.

## Why these records form one chain

The chain is not based only on temporal proximity. It is supported by independent identifiers and semantics:

1. Security 4624 creates actor session `0x79779`; Security 4672 and each change event use the same Logon ID.
2. Sysmon records the same `User` and `LogonId`, plus exact target name and group in the commands.
3. The target Security ID/name in 4720, 4722, 4724, 4738, 4732, and 4726 is consistent.
4. `net user /add` semantically explains the account events; `net localgroup ... /add` explains 4732; `net user /del` explains 4726.
5. The decoded parent command explicitly identifies `Invoke-AtomicTest T1136.001` and its cleanup action.
6. Sysmon `ProcessGuid` values distinguish separate process instances even where Windows reuses PID `5104` three seconds later.

## Evidence status

### Confirmed

- Actor: `ATTACKRANGE\Administrator`
- Creation session: `0x79779` (decimal `497529`)
- Cleanup session: `0x7FE66` (decimal `523878`)
- Target: `ATTACKRANGE\T1136.001_Admin`
- Privileged group: `BUILTIN\Administrators`
- Account creation, enablement, password setting, UAC modification, membership addition, and deletion
- Causative `cmd.exe -> net.exe -> net1.exe` process chain
- Controlled Atomic Red Team test context

### Not observed in the selected files

- 4624 or 4625 for the target account
- 4648 using the target credentials
- 4672 for the target account
- Sysmon Event 1 with the target as the executing `User`
- Explicit 4733 member removal
- Target-driven service, scheduled task, policy, account, or remote-host changes

### Not available from the dataset

- Change ticket, approver, approved maintenance window, or CMDB/IAM request
- Immutable numeric target SID, Directory Object ID, or Distinguished Name
- Reliable actor source IP for the local service-mediated logon
- Complete cross-host EDR, network, email, or ticketing telemetry

## Key field relationships

### Subject versus target

In account-management events, **Subject** is the security principal whose session performed the action; **Target/New Account/Member** is the principal changed. In 4720, `ATTACKRANGE\Administrator` is the Subject and `ATTACKRANGE\T1136.001_Admin` is the New Account. In 4732, the Subject is still Administrator, the Member is the new principal, and the target group is `BUILTIN\Administrators`.

Security 4624 uses the words differently: the Subject (`NETWORK SERVICE`) requested a logon, while **New Logon** identifies the Administrator session later used as the Subject of the change events.

### SubjectLogonId

`0x79779` is the session key joining the actor's 4624 New Logon, 4672, Sysmon processes, and 4720–4732 change events on the same host. It does not identify the target account. Logon IDs are host/session scoped and can be reused after reboot; they are not enterprise-wide identifiers.

### SID and account identity

In an ideal raw event, the immutable numeric SID should join the target across rename operations. This rendered dataset resolves Security IDs to account names, so the numeric SID is **Not available**. The chain is still strongly supported by the unique target string, domain, host, actor Logon ID, exact commands, event semantics, and controlled-test provenance, but it cannot demonstrate SID-based rename tracking.

If an account were renamed, name-only matching could split one identity into two apparent users. A production investigation should pivot on numeric SID or Entra Object ID, then use name as a display attribute.

### Group type and Event IDs

- **4728:** a member is added to a security-enabled global group. Global groups normally collect principals from the same domain and can be granted access across trusted domains.
- **4732:** a member is added to a security-enabled local group. On a workstation/member server this can be a local SAM group; on a domain controller it can be a domain-local group such as the Builtin Administrators group.
- **4756:** a member is added to a security-enabled universal group. Universal membership can span domains and is replicated through the Global Catalog.

The Event ID alone is not sufficient; `Computer`, `Group Domain`, group SID, and directory context determine whether “local” means host-local or AD domain-local.

### EventRecordID and ordering

EventRecordID/RecordNumber is meaningful only within the same log channel on the same computer. Records 228839–228844 can order the Security events because they are all from the Security channel on the same DC. They must not be compared numerically with Sysmon EventRecordID 4277 or with records from another host.

### Hexadecimal IDs and PIDs

- `0x79779` = decimal `497529`
- `0x7FE66` = decimal `523878`
- `0x54C` = decimal `1356`
- Sysmon PID `4764` = hexadecimal `0x129C`

PIDs are reusable. In this dataset, PID `5104` appears in both creation and cleanup process chains, but the Sysmon `ProcessGuid` values differ. `ProcessGuid` plus host/time is therefore safer than PID alone.

### Event 4672

4672 means a new logon session received one or more sensitive privileges. It does not prove those privileges were exercised, that the logon was malicious, or that a newly created account received them. Here the observed 4672 belongs to `Administrator` actor sessions; no 4672 for `T1136.001_Admin` was found.

## Initial impact and response decision

The privileged membership technically took effect, but only for a short controlled-test interval. The account was then deleted and no use of the target identity was observed. No lab containment is required beyond verifying cleanup, which 4726 and Sysmon confirm.

For the equivalent production event:

1. Validate the ticket, approver, requested target, exact group, execution identity, and maintenance window.
2. If authorization cannot be established quickly, remove the membership and disable the target while preserving logs.
3. If the actor session is unexplained or compromised, isolate the originating administrative host and reset/revoke actor credentials.
4. Hunt by target SID/Object ID, actor Logon ID, group SID, command/process lineage, and other changes from the same actor.
5. Confirm rollback with a 4733/4729/4757 event or account disable/delete event, and verify that no orphaned access path remains.

## Query-batch decision

A second query batch is not required. The first concentrated pass covered all fields present in the chosen files. The remaining gaps are evidence categories absent from the dataset rather than unanswered queries against available data.
