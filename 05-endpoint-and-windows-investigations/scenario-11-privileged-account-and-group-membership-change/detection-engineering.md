# Detection Engineering

## Objective

Detect privileged group additions with enough context to answer three separate questions:

1. Did the membership change occur?
2. Was a newly created or otherwise unusual account involved?
3. Did the target identity subsequently use the new privilege?

Ticket and maintenance-window data should enrich the alert and help determine intent. They must not suppress the technical fact without an explicit, tested exception process.

## Required telemetry

| Purpose | Preferred evidence |
| --- | --- |
| Group membership additions | Security 4728, 4732, 4756 |
| Group membership removals | Security 4729, 4733, 4757 |
| Account lifecycle | Security 4720, 4722, 4724, 4725, 4726, 4738 |
| Actor session | Security 4624, 4648, 4672 and SubjectLogonId |
| Target use | Security 4624/4625/4648/4672; Sysmon or EDR process telemetry |
| Causative command | Security 4688, Sysmon Event 1, PowerShell, or EDR process lineage |
| Directory detail | Security 5136 and AD object/SID enrichment where configured |
| Business context | Ticket, approver, approved window, IAM workflow, asset criticality |

Microsoft requires the Audit Security Group Management subcategory to collect the core 4728/4729/4732/4733/4756/4757 events. Production engineering should verify policy and ingestion on domain controllers and managed endpoints before treating silence as a negative finding.

## Layered analytics

### Layer 1 — privileged membership addition

Alert on 4728, 4732, or 4756 when the target group matches a maintained high-risk group inventory. Start with groups such as:

- Administrators;
- Domain Admins;
- Enterprise Admins;
- Schema Admins;
- Account Operators;
- Server Operators;
- Backup Operators;
- DnsAdmins;
- Remote Desktop Users where remote access is sensitive;
- organisation-specific VPN, EDR, IAM, virtualisation, and backup administrator groups.

The portable Sigma template is in [`detections/windows-privileged-group-membership-addition.yml`](detections/windows-privileged-group-membership-addition.yml).

### Layer 2 — new account followed by privileged membership

Correlate account creation with a privileged addition on the same authoritative host within 15 minutes. Prefer immutable member SID or Object ID. If only names are available, normalise domain/name carefully and label the correlation as lower confidence.

This scenario validates the sequence:

```text
4720 target created
  -> 4722/4724/4738 target prepared
  -> 4732 same target added to Administrators
```

### Layer 3 — post-change privilege use

Increase severity when the member subsequently:

- logs on successfully, especially to a domain controller or tier-0 system;
- receives Event 4672 on its own Logon ID;
- is used in Event 4648 explicit credentials;
- launches administrative or credential-access processes;
- modifies another user, group, service, task, GPO, security tool, or audit policy;
- authenticates from a new source, unmanaged device, or unusual geography.

No Layer 3 activity by `T1136.001_Admin` was observed in this scenario.

## Splunk SPL examples

These are deployment templates. Field names depend on the Splunk Windows TA, CIM mapping, and local parsing. Validate them against the target environment before enabling alert actions.

### Direct privileged-group addition

```spl
`wineventlog_security`
EventCode IN (4728, 4732, 4756)
(TargetUserName IN ("Administrators", "Domain Admins", "Enterprise Admins", "Schema Admins", "Account Operators", "Server Operators", "Backup Operators", "DnsAdmins")
 OR Group_Name IN ("Administrators", "Domain Admins", "Enterprise Admins", "Schema Admins", "Account Operators", "Server Operators", "Backup Operators", "DnsAdmins"))
| eval actor=coalesce(SubjectDomainName."\\".SubjectUserName, src_user)
| eval member=coalesce(MemberName, MemberSid, user)
| eval privileged_group=coalesce(TargetUserName, Group_Name)
| table _time dest EventCode actor SubjectLogonId member privileged_group
```

### Newly created account added to Administrators

This adapts Splunk Security Content's public `Detect New Local Admin account` analytic by reducing the maximum span and preserving actor and target context:

```spl
`wineventlog_security`
(EventCode=4720 OR (EventCode=4732 AND (Group_Name="Administrators" OR TargetUserName="Administrators")))
| transaction user dest connected=false maxspan=15m
| stats count min(_time) AS firstTime max(_time) AS lastTime
        dc(EventCode) AS distinct_eventcodes
        values(EventCode) AS eventcodes
        values(src_user) AS actors
        values(Group_Name) AS groups
  BY user dest
| where distinct_eventcodes > 1
```

Before production use, verify that the normalised `user` field represents the created account in 4720 and the added member in 4732. Where that mapping is unreliable, correlate on immutable SID/Object ID through a lookup or data-model enrichment.

### Target-use hunt after a change

```spl
`wineventlog_security`
EventCode IN (4624, 4625, 4648, 4672)
(TargetUserName="<target_account>" OR SubjectUserName="<target_account>")
| table _time dest EventCode SubjectUserName SubjectLogonId TargetUserName TargetLogonId LogonType IpAddress ProcessName
| sort 0 _time
```

Run an equivalent EDR/Sysmon hunt using the target SID/account as the executing user. Keep 4672 tied to its own Subject and Logon ID; do not attribute an actor's 4672 to the member account merely because it occurred nearby.

## Local validation

[`scripts/validate_detection.py`](scripts/validate_detection.py) evaluates the derived event timeline without requiring a SIEM. The committed result is [`evidence/processed/detection-validation.csv`](evidence/processed/detection-validation.csv).

Expected results:

| Analytic | Expected | Observed |
| --- | ---: | ---: |
| Privileged membership addition | 1 | 1 |
| New account followed by privileged addition within 15 minutes | 1 | 1 |
| Post-change activity executed as target | 0 | 0 |

This validates the scenario logic, not a production parser. The Sigma and SPL implementations still require environment-specific field and performance testing.

## Tuning and severity

### Recommended severity model

| Condition | Suggested severity |
| --- | --- |
| Privileged group addition with complete approved context | Medium / review |
| Addition on a domain controller or tier-0 asset | High |
| New account plus privileged addition | High |
| Target logs on or receives 4672 shortly afterward | Critical |
| Unknown actor, missing approval, or out-of-window change | High to Critical |
| Confirmed controlled test with verified cleanup | Informational / close after evidence review |

### Safe tuning

- use group SIDs where possible so renamed or localised group names remain covered;
- enrich known automation accounts, but alert when they act outside expected hosts or workflows;
- compare the exact actor, target, group, ticket, and change window;
- maintain an expiration date for exceptions;
- detect both additions and rollback/removal events;
- alert separately when the actor adds itself to a privileged group;
- avoid broad suppression of Administrator, SYSTEM, domain-join, or IAM activity.

## Known false-positive or benign contexts

- approved IAM or joiner/mover/leaver workflows;
- endpoint provisioning or domain join;
- emergency break-glass access with retrospective approval;
- backup, virtualisation, EDR, or deployment tooling;
- controlled security validation such as Atomic Red Team;
- approved temporary access that is removed on schedule.

Each is a possible explanation, not automatic proof. Verify the actor, target, group, host, requested scope, approver, window, and rollback.

## References

- [MITRE DET0310 — Suspicious Addition to Local or Domain Groups](https://attack.mitre.org/detectionstrategies/DET0310/)
- [MITRE T1098.007 — Additional Local or Domain Groups](https://attack.mitre.org/techniques/T1098/007/)
- [Microsoft Event 4732](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4732)
- [Microsoft Defender for Identity — configure Windows event auditing](https://learn.microsoft.com/en-us/defender-for-identity/deploy/configure-windows-event-collection)
- [Splunk Security Content — Detect New Local Admin Account](https://research.splunk.com/endpoint/b25f6f62-0712-43c1-b203-083231ffd97d/)
