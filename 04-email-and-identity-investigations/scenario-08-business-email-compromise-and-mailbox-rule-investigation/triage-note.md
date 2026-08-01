# Triage Note

## Alert or trigger

Review of Microsoft 365 ExchangeAdmin audit records showing successful mailbox delegation, Inbox-rule, and forwarding configuration changes.

## Initial question

Do the records represent legitimate administration, suspicious mailbox persistence or email hiding, attempted email collection, a confirmed mailbox compromise, or a successful BEC incident?

## Initial severity

**High**

The severity is based on successful high-risk mailbox changes, including:

- SendAs and FullAccess permission grants;
- rules that delete, mark as read, or move messages;
- StopProcessingRules on multiple hiding rules;
- forwarding to external-looking destinations;
- three mailboxes configured to forward to the same Gmail destination in 66 seconds;
- two accounts creating forwarding rules to the same destination within 2 minutes 30 seconds.

Severity represents response priority. It does not establish malicious intent.

## Time range

2023-05-29 11:47:56 UTC to 2024-10-08 05:11:07 UTC.

The range spans independent simulation samples. It is not treated as the duration of one incident.

## Entities

### Actors

- stinger@contoso.onmicrosoft.com
- Matt@contoso.onmicrosoft.com
- adam@contosomovement.onmicrosoft.com
- adam@contoso.onmicrosoft.com

### Named delegate

- Lidia@contoso.onmicrosoft.com

### Named mailbox

- Henrietta@contoso.onmicrosoft.com

### External or forwarding destinations

- johndoe@gmail[.]com
- bla@bla[.]com
- alpha@localhost[.]com

### Notable source addresses

- 104.28.196[.]199
- 41.203.78[.]171
- 154.66.247[.]79
- two IPv6 source addresses recorded in the delegation and rule-change samples

### Unresolved targets

Several mailboxes and trustees are represented only by GUIDs. The available offline data does not map every GUID to a mailbox owner.

## Available evidence

- nine Microsoft 365 audit sample files;
- 14 raw records;
- 12 unique events after deduplication;
- operation result, actor, source IP, tenant, target, parameters, session, and event identifiers;
- processed UTC timeline.

## Unavailable evidence

- Entra sign-in, MFA, Conditional Access, and device context;
- administrator approvals and change records;
- live Inbox-rule, mailbox-forwarding, and permission state;
- message trace and mailbox-access logs;
- fraudulent messages, recipient action, and payment records.

## Initial findings

1. All 12 unique operations recorded ResultStatus=True.
2. Four rules could reduce visibility of incoming mail by deleting, marking as read, or moving messages.
3. Six events configured mailbox or Inbox-rule forwarding.
4. Two events added high-impact mailbox permissions.
5. The strongest behavioural cluster is the 2024-03-10 sequence: one actor configured three different mailbox targets to forward to the same Gmail address in 66 seconds.
6. The nine files are separate simulated samples and cannot be combined into one confirmed BEC case.

## Triage assessment

**True Positive - Suspicious mailbox configuration activity confirmed; authorisation, compromise, message delivery, exfiltration, and BEC impact not confirmed.**

## Immediate triage actions in a live environment

1. Validate each change against an approved request and the mailbox owner.
2. Preserve current rules, forwarding values, and permission state before removal.
3. If unauthorised, disable or remove the configuration, revoke relevant sessions, and secure affected identities.
4. Query sign-in, mailbox-access, send, and message-trace data around each event.
5. Escalate immediately if forwarding reached a real external recipient, if SendAs was used, or if finance-related messages were accessed or sent.

