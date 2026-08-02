# Investigation Report

## Executive summary

Windows Security and Sysmon evidence confirms that `ATTACKRANGE\Administrator` created `ATTACKRANGE\T1136.001_Admin`, enabled it, set its password, changed its account-control attributes, and added it to `BUILTIN\Administrators` on `win-dc-7216619.attackrange.local`.

The group membership change is a **true positive**. The activity is classified as a **legitimate authorised controlled security test**, not because Administrator performed it, but because independent test metadata and the decoded process commands identify Atomic Red Team `T1136.001` execution and cleanup. Production ticket, approver, and maintenance-window records are not available.

No logon, explicit-credential event, special-privilege event, or process execution by the target identity was observed. The target was deleted approximately three seconds after creation. There is no evidence in the selected telemetry that the newly granted access was exercised.

## Scope

### Included

- Windows Security rendered log: 5,494 records
- Sysmon Operational XML log: 6,386 records
- Atomic Red Team metadata
- Primary host and target-identity slice
- Account lifecycle, privileged membership, actor session, process lineage, target use, and cleanup checks

### Excluded or unavailable

- Ticketing, approval, CMDB, and maintenance-window systems
- Immutable numeric target SID, directory Object ID, and distinguished name
- Full cross-host EDR and network telemetry
- A usable actor source IP

## Evidence integrity

Exact source hashes, sizes, counts, time ranges, and handling decisions are recorded in [`evidence-inventory.md`](evidence-inventory.md) and [`evidence/processed/dataset-profile.csv`](evidence/processed/dataset-profile.csv). Raw artifacts are kept local. The public evidence is filtered, minimised, and sanitised; the static teaching password is not published.

## Detailed findings

### 1. Actor session

Security Event 4624, Record 228808, created network Logon Type 3 session `0x79779` for `ATTACKRANGE\Administrator`. Event 4672, Record 228809, assigned sensitive privileges to that same actor session.

This 4672 event does not show that the target account received or used special privileges. Its Subject and Logon ID identify the Administrator actor.

### 2. Account creation and preparation

At 10:41:26, the same Subject and Logon ID generated:

| Event | Record | Confirmed action |
| ---: | ---: | --- |
| 4720 | 228839 | Created `ATTACKRANGE\T1136.001_Admin` |
| 4722 | 228840 | Enabled the account |
| 4724 | 228841 | Set/reset the account password |
| 4738 | 228842 | Updated Password Last Set and changed UAC `0x15 -> 0x10` |

Sysmon independently records the `net user /add` command under Administrator and Logon ID `0x79779`.

### 3. Privileged membership change

Event 4732, Record 228843, records the target member being added to `BUILTIN\Administrators` by `ATTACKRANGE\Administrator`, again under `0x79779`. Sysmon records the corresponding `net localgroup administrators ... /add` process chain.

This is sufficient to confirm that the membership change occurred. It does not answer whether the change was authorised or whether the target later used the access; those are separate questions.

### 4. Authorisation context

The following evidence supports a controlled-test classification:

- the official Splunk Attack Range dataset identifies an Atomic Red Team test;
- the decoded parent command invokes `Invoke-AtomicTest "T1136.001"`;
- the cleanup parent command invokes the same test with `-Cleanup`;
- the create, group-add, and delete commands match the audit events and target exactly.

A production change ticket, approver, and approved window are **Not available**. The lab metadata proves simulation intent but is not a substitute for production change-control evidence.

### 5. Post-change behaviour

The selected Security and Sysmon files were searched for target-attributed activity. The following were **Not observed**:

- successful or failed target logon, Events 4624 or 4625;
- explicit credential use involving the target, Event 4648;
- target special-privilege assignment, Event 4672;
- Sysmon Event 1 with the target as executing user;
- target-driven account, service, task, policy, or remote-host activity;
- an explicit 4733 member-removal event.

These negative findings mean that no target use was found in available telemetry. They do not prove that no activity occurred outside the available host and data sources.

### 6. Cleanup

Administrator cleanup session `0x7FE66` launched `net user /del T1136.001_Admin`. Event 4726, Record 228888, confirms deletion at 10:41:29, approximately three seconds after creation.

Although an explicit 4733 removal was not observed, account deletion removes the principal. In production, responders should still verify current group membership, disablement/deletion state, active sessions, tokens, scheduled tasks, services, and other access paths.

## Correlation assessment

The event chain is supported by:

1. the same host and Security channel;
2. the same actor and `SubjectLogonId` across lifecycle and membership events;
3. the same target identity across 4720, 4722, 4724, 4738, 4732, and 4726;
4. exact account and group names in corroborating Sysmon command lines;
5. Sysmon `ProcessGuid` and parent-child relationships;
6. Atomic test execution and cleanup semantics;
7. EventRecordID ordering only within each host/channel, not across Security and Sysmon.

The conclusion therefore does not rely on temporal proximity alone.

## Final classification

| Decision dimension | Assessment |
| --- | --- |
| Technical detection | True Positive |
| Privileged membership actually changed | Confirmed |
| Authorisation / intent | Legitimate controlled security test |
| Process compliance | Cannot be evaluated; ticket and approval data not available |
| Target use after change | Not observed |
| Persistence remaining | Target deletion confirmed; broader environment not available |
| Lab containment | Not required |
| Production analogue | High-priority validation; contain if authorisation is absent or inconsistent |

## ATT&CK assessment

- **T1098.007 — Additional Local or Domain Groups:** primary mapping for adding the account to Administrators.
- **T1136.001 — Create Account: Local Account:** retained as the source Atomic test label.
- **T1136.002 — Create Account: Domain Account:** better fits the domain-controller audit semantics and `ATTACKRANGE` target principal.

## Conclusion

The account and privilege changes were real, correctly detected, and rapidly cleaned up. Available evidence supports authorised simulation rather than unauthorised escalation. The most important analytical distinction is that a true-positive technical event may still be an authorised business action, while an Administrator actor or a nearby 4672 event is not, by itself, proof of authorisation, maliciousness, or target-account use.
