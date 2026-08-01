# Investigation Report

## Executive summary

Nine public Microsoft 365 audit sample files were examined for mailbox delegation, email-hiding, and forwarding behaviour. A corrected parser handled both direct JSON events and JSON nested in CSV AuditData fields.

The parser extracted 14 raw records and deduplicated them into 12 unique events:

- 2 mailbox permission changes;
- 4 email-hiding rule changes;
- 6 forwarding changes.

All unique events recorded ResultStatus=True. The highest-confidence suspicious sequence occurred on 2024-03-10, when one actor configured three different mailbox targets to forward to the same Gmail destination in 66 seconds.

The available evidence confirms successful mailbox configuration changes consistent with BEC-related techniques. It does not confirm account compromise, successful email delivery or collection, fraudulent sending, recipient action, or financial loss.

## Investigation questions

1. Which mailbox permissions, rules, and forwarding settings changed?
2. Which changes could conceal or collect email?
3. Which events can be reliably grouped?
4. Do the records prove mailbox compromise or BEC?
5. What evidence and response would be required in a live environment?

## Scope and methodology

### Included

- nine ExchangeAdmin audit samples;
- record parsing and normalisation;
- deduplication by tenant and event Id;
- UTC timeline reconstruction;
- comparison of actor, tenant, IP, session, target, and parameters;
- interpretation of Exchange rule and permission semantics;
- ATT&CK mapping at the behaviour level.

### Excluded

- live tenant queries;
- IP reputation or geolocation-based attribution;
- assumptions about account ownership where only GUIDs are available;
- claims that separate source files form one continuous attack;
- conclusions about message contents, delivery, user activity, or financial impact.

## Evidence processing

The first timeline attempt parsed only the five JSON files. The four CSV files were traversed but not decoded because their audit events were stored as JSON strings in the AuditData column.

The corrected parser:

1. validates the expected nine filenames;
2. parses JSON files directly;
3. parses CSV rows with csv.DictReader;
4. decodes each AuditData value as JSON;
5. extracts records containing Operation;
6. deduplicates by OrganizationId and event Id;
7. sorts by CreationTime;
8. writes mailbox-activity-timeline.csv.

Final validation:

~~~text
Files processed: 9
Raw event records: 14
Unique events: 12
Duplicate copies removed: 2
~~~

## Timeline overview

| Cluster | Time UTC | Confirmed activity | Correlation assessment |
| --- | --- | --- | --- |
| A | 2023-05-29 11:47:56 | SendAs permission granted | Independent permission sample |
| B | 2023-05-29 12:29:35-12:30:51 | Subject-based deletion rule and mailbox forwarding | Strong shared session, IP, tenant, and target; different UserId values require caution |
| C | 2023-06-04 03:14:58 | Invoice rule moved messages to Deleted Items | Independent rule-update sample |
| D | 2023-07-23 12:32:53 | FullAccess granted to Lidia on Henrietta's mailbox | Independent permission sample |
| E | 2024-02-04 22:49:32 | Dot-named rule marked mail as read and moved it to Deleted Items | Independent hiding-rule sample |
| F | 2024-03-10 21:03:37-21:04:43 | Three mailbox targets forwarded to one Gmail address | Strong 66-second multi-mailbox cluster |
| G | 2024-10-07 23:46:37-2024-10-08 05:11:07 | Archive hiding rule, then two same-destination forwarding rules | Same tenant and IP; forwarding pair strongly related; earlier hiding rule only possibly related |

The full 12-event record is documented in mailbox-rule-analysis.md and the processed CSV timeline.

## Findings

### Finding 1 - Additional mailbox permissions

One event granted SendAs to a GUID-identified trustee. One event granted Lidia FullAccess to Henrietta's mailbox.

These changes can provide impersonation or mailbox-content access if unauthorised. The audit records do not contain approval data, actual mailbox access, or SendAs usage.

**Assessment:** Successful high-impact permission changes; authorisation and malicious use unconfirmed.

### Finding 2 - Email-hiding rules

Four rules reduced message visibility:

- subject Attention moved to Deleted Items;
- subject invoice moved to Deleted Items;
- a dot-named rule marked messages as read and moved them to Deleted Items;
- a dot-named rule marked messages as read and moved them to Archive.

All four used StopProcessingRules=True. Two records showed no filter condition in their available Parameters.

**Assessment:** High-risk hiding behaviour confirmed; affected messages and business impact unconfirmed.

### Finding 3 - Mailbox-level forwarding

Four Set-Mailbox events configured forwarding:

- one mailbox to bla@bla[.]com;
- three different mailbox targets to johndoe@gmail[.]com.

Each used DeliverToMailboxAndForward=True, which preserves a local copy while forwarding another copy.

**Assessment:** Successful forwarding configuration confirmed; successful forwarding of actual messages and exfiltration unconfirmed.

### Finding 4 - Inbox-rule forwarding

Two accounts created ForwardToHeaven rules pointing to alpha@localhost[.]com from the same source IP and port, in the same tenant, 2 minutes 30 seconds apart.

**Assessment:** Strongly associated same-destination forwarding activity; recipient type and deliverability unconfirmed.

### Finding 5 - Evidence is not one complete BEC incident

The source data spans different dates, tenants, identities, and independent simulation files. Some fields are reused in ways that should not be interpreted as real session continuity.

**Assessment:** The dataset demonstrates several BEC-related techniques but cannot support a single incident narrative.

## Impact assessment

### Confirmed

- Exchange accepted 12 unique configuration operations.
- SendAs and FullAccess permissions were added.
- Inbox rules were created or changed to delete, mark as read, move, or forward messages.
- Mailbox-level forwarding was configured.
- Three different mailbox targets were configured to the same Gmail destination in 66 seconds.

### Reasonably inferred

- The hiding rules could suppress messages from the normal Inbox view.
- The forwarding configurations could copy future messages to the configured recipients.
- The permissions could enable additional mailbox access or impersonation if exercised.
- The rapid repeated forwarding patterns warrant high-priority investigation.

### Not observed

Not observed is not used for message delivery or financial activity because the required data sources were not provided.

### Not available

- authentication and MFA context;
- live rule and permission state;
- message trace and mailbox access;
- SendAs send activity;
- recipient interaction;
- payment or finance-system records.

### Unable to confirm

- whether any actor was unauthorised;
- whether any account or session was compromised;
- whether rules processed actual messages;
- whether messages reached an external destination;
- whether information was collected or exfiltrated;
- whether fraudulent communication or financial loss occurred.

## Classification

**True Positive - Suspicious mailbox delegation, email-hiding, and forwarding configuration changes confirmed in simulated audit records.**

**BEC status:** Not confirmed.

**Mailbox compromise:** Unable to confirm.

**Financial impact:** Unable to confirm; financial evidence was not available.

**Confidence:** High for operation and parameter interpretation; low for actor intent and business impact.

## ATT&CK mapping

| Technique | Mapping rationale | Boundary |
| --- | --- | --- |
| T1098.002 Additional Email Delegate Permissions | SendAs and FullAccess grants | Does not prove malicious persistence |
| T1114.003 Email Forwarding Rule | Mailbox and Inbox-rule forwarding | Does not prove collection or exfiltration |
| T1564.008 Email Hiding Rules | Delete, mark-as-read, Archive, Deleted Items, stop processing | Does not prove messages were actually hidden |

## Detection opportunities

### High-priority detections

1. Alert on Add-MailboxPermission or Add-RecipientPermission involving FullAccess, SendAs, or SendOnBehalf when no approved change exists.
2. Alert on New-InboxRule or Set-InboxRule using DeleteMessage, MarkAsRead, MoveToFolder=Deleted Items or Archive, or StopProcessingRules.
3. Alert on Set-Mailbox when ForwardingAddress or ForwardingSmtpAddress is added or changed.
4. Correlate one actor or source IP modifying multiple mailboxes within a short window.
5. Correlate multiple accounts forwarding to the same destination.
6. Increase severity when hiding and forwarding changes occur near suspicious sign-in activity.

### Required tuning

- approved shared-mailbox delegates;
- known service accounts and migration tools;
- authorised forwarding destinations;
- help-desk and Exchange administrator maintenance windows;
- bulk changes linked to approved tickets;
- mailbox importance and finance or executive role.

### Required enrichment

- Entra sign-in result and authentication details;
- MFA and Conditional Access status;
- actor and target role;
- IP and device baseline;
- current rule and permission state;
- message trace and mailbox-access data;
- change-ticket identifier.

## Final conclusion

The investigation confirms 12 successful mailbox configuration events demonstrating delegation, email hiding, and forwarding behaviours. These events are relevant to BEC detection and response, but the evidence is configuration-focused and simulated. The defensible conclusion is suspicious BEC-related activity, not confirmed mailbox compromise, confirmed data exfiltration, or successful BEC.

