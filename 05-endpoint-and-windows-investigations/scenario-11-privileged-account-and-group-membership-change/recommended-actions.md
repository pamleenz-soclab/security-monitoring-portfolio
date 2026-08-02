# Recommended Actions

## Decision principle

A privileged membership event has two independent dimensions:

1. **Technical truth:** did the account or group change occur?
2. **Business legitimacy:** was the exact actor, target, group, host, time, and duration approved?

An authorised change remains a true-positive technical detection. An unauthorised change performed by a known administrator remains a security incident.

## Actions for this controlled dataset

- Confirm cleanup through the Atomic `-Cleanup` process chain and Event 4726.
- Record that no target logon, explicit-credential use, target 4672, or target process execution was observed.
- Close as an authorised controlled test.
- Retain the detection hit as validation evidence instead of marking it false positive.
- Do not perform lab containment; the target has already been deleted.

## Production response workflow

### 1. Validate scope and authorisation

Confirm all of the following against authoritative records:

- change or access-request ticket;
- requester and approver;
- actor account and originating administrative workstation;
- target SID/Object ID, not only the display name;
- exact group/role and business purpose;
- approved start, expiry, and removal time;
- whether the change was manual or performed by an expected IAM tool;
- whether the host is a domain controller, tier-0 system, backup platform, hypervisor, EDR console, or other high-impact asset.

If the dataset contains no ticket source, record **Not available**. If the ticket source was queried and no matching record exists, record **Not observed**.

### 2. Preserve evidence

- Export the original Security, Sysmon/EDR, directory audit, identity-provider, and administrative-host records.
- Record host/channel/time-zone context and event record identifiers.
- Preserve the actor Logon ID, target SID/Object ID, group SID, process lineage, command line, source IP/device, and correlation/activity IDs.
- Hash exported evidence and document collection time and analyst handling.
- Avoid deleting the account before required forensic evidence and current-access state are captured, unless immediate harm requires emergency containment.

### 3. Contain when authorisation is absent or inconsistent

Use the least destructive action that stops the risk:

- remove the target from the privileged group;
- disable the target account;
- revoke active sessions, tokens, tickets, and refresh tokens where applicable;
- rotate/reset target credentials and any exposed recovery material;
- if the actor is unexplained or compromised, disable or restrict it and rotate its credentials;
- isolate the originating administrative endpoint when endpoint compromise is suspected;
- block malicious remote-management paths or source infrastructure where supported by evidence;
- protect domain controllers and tier-0 systems from further access while preserving operations.

Emergency containment should be documented and followed by authorised recovery actions.

### 4. Expand the investigation

Hunt on stable identifiers and linked sessions:

- all changes by the same `SubjectUserSid` and `SubjectLogonId`;
- all groups or roles receiving the same member SID/Object ID;
- account creation, enablement, password reset, rename, attribute changes, delegation, and deletion;
- 4624/4625 logons, 4648 explicit credentials, 4672 privileges, Kerberos/NTLM authentication, and remote access;
- process, service, scheduled-task, registry, GPO, security-tool, and audit-policy changes;
- lateral movement and activity on other hosts;
- other new accounts created by the same actor or process lineage;
- removal/rollback events and any re-addition after containment.

Account names are mutable. Pivot on SID/Object ID when available so a rename does not break the investigation chain.

### 5. Remediate the root cause

Depending on findings:

- correct the IAM or deployment workflow that granted excessive access;
- enforce just-in-time and time-limited privileged access;
- separate ordinary and administrative identities;
- require controlled privileged access workstations for tier-0 changes;
- remove stale or nested group memberships;
- review delegated rights that allowed the change;
- harden or rebuild a compromised administrative endpoint;
- reset credentials and review MFA methods for affected identities;
- correct auditing, log forwarding, retention, and time synchronisation gaps.

### 6. Verify recovery

Do not close only because a removal command was issued. Confirm:

- Event 4729, 4733, or 4757, or authoritative current group membership;
- account disabled/deleted state through directory and endpoint checks;
- privileged sessions and tokens revoked;
- scheduled tasks, services, SSH keys, application roles, certificates, and delegated access removed;
- no re-addition or alternate privileged account appears;
- monitoring remains healthy after remediation.

## Escalation thresholds

Escalate urgently when any of these apply:

- Domain Admins, Enterprise Admins, Schema Admins, Administrators, or equivalent tier-0 role affected;
- new account immediately receives privileged membership;
- actor is unknown, disabled, service-like but interactive, or operating from an unexpected device;
- target logs on, receives 4672, or performs administrative actions shortly after the change;
- change occurs outside an approved window or conflicts with the ticket;
- multiple accounts or groups are modified by the same session;
- logging, EDR, backup, identity, or security controls are subsequently changed;
- rollback fails, is incomplete, or the account is re-created.

## Monitoring improvements

- Collect account and security-group management events from domain controllers and endpoints.
- Collect 4624, 4648, 4672, process creation, and relevant directory changes.
- Normalise Subject, target/member, group, SID/Object ID, Logon ID, host, and time fields.
- Enrich alerts with asset tier, group criticality, identity owner, ticket, approver, and expiration.
- Build separate analytics for direct group addition, new-account correlation, self-addition, and post-change use.
- Test detections with controlled simulations and retain true-positive validation records.
