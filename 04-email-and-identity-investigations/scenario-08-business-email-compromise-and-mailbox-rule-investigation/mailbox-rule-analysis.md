# Mailbox Rule and Permission Analysis

## Scope

This document interprets the 12 unique Exchange audit events produced from nine source files. The exact record-level fields remain in evidence/processed/mailbox-activity-timeline.csv.

## Event inventory

| # | Time UTC | Operation | Actor | Main change | Risk |
| ---: | --- | --- | --- | --- | --- |
| 1 | 2023-05-29 11:47:56 | Add-RecipientPermission | stinger@contoso.onmicrosoft.com | Granted SendAs to a GUID-identified trustee on a GUID-identified recipient | High |
| 2 | 2023-05-29 12:29:35 | New-InboxRule | stinger@contoso.onmicrosoft.com | Rule Direct: subject contains Attention, move to Deleted Items, stop later rules | High |
| 3 | 2023-05-29 12:30:51 | Set-Mailbox | Matt@contoso.onmicrosoft.com | Forward mailbox to bla@bla[.]com and retain a local copy | High |
| 4 | 2023-06-04 03:14:58 | Set-InboxRule | Matt@contoso.onmicrosoft.com | Rule Accounts: subject contains invoice, move to Deleted Items, stop later rules | High |
| 5 | 2023-07-23 12:32:53 | Add-MailboxPermission | stinger@contoso.onmicrosoft.com | Granted Lidia FullAccess to Henrietta's mailbox | Medium |
| 6 | 2024-02-04 22:49:32 | New-InboxRule | stinger@contoso.com | Rule named .: mark as read, move to Deleted Items, stop later rules | High |
| 7 | 2024-03-10 21:03:37 | Set-Mailbox | adam@contosomovement.onmicrosoft.com | Forward target mailbox 1 to johndoe@gmail[.]com and retain a local copy | High |
| 8 | 2024-03-10 21:04:24 | Set-Mailbox | adam@contosomovement.onmicrosoft.com | Forward target mailbox 2 to johndoe@gmail[.]com and retain a local copy | High |
| 9 | 2024-03-10 21:04:43 | Set-Mailbox | adam@contosomovement.onmicrosoft.com | Forward target mailbox 3 to johndoe@gmail[.]com and retain a local copy | High |
| 10 | 2024-10-07 23:46:37 | New-InboxRule | stinger@contoso.onmicrosoft.com | Rule named .: mark as read, move to Archive, stop later rules | High |
| 11 | 2024-10-08 05:08:37 | New-InboxRule | adam@contoso.onmicrosoft.com | Rule ForwardToHeaven: forward to alpha@localhost[.]com | High |
| 12 | 2024-10-08 05:11:07 | New-InboxRule | stinger@contoso.onmicrosoft.com | Rule ForwardToHeaven: forward to alpha@localhost[.]com | High |

Risk ratings assume no approved business justification has yet been confirmed.

## Permission changes

### SendAs permission

The Add-RecipientPermission event successfully assigned AccessRights=SendAs. Microsoft documents that SendAs allows the trustee to send messages that appear to come directly from the target recipient.

The target and trustee are GUIDs:

- target recipient: e4ad2d28-703e-4189-9752-6b827ef9107d;
- trustee: 311b45d6-1a3e-46ac-8434-721367961e19.

The available data does not resolve these GUIDs to named accounts and does not contain send events. The permission grant is confirmed; impersonation and malicious use are not.

### FullAccess permission

The Add-MailboxPermission event successfully granted Lidia FullAccess to Henrietta's mailbox with InheritanceType=All.

FullAccess enables access to mailbox contents but does not, by itself, include SendAs or SendOnBehalf. The permission grant is confirmed; mailbox access and malicious use are not.

## Email-hiding rules

### Direct rule

Parameters:

- Name=Direct
- SubjectContainsWords=Attention
- DeleteMessage=True
- StopProcessingRules=True

Messages matching the subject condition would be moved to Deleted Items. StopProcessingRules prevents later rules from processing a matched message.

The word Attention is broad and could include security or business notifications. The rule is suspicious, but the audit event does not show which messages matched it.

### Accounts rule

Parameters:

- Identity=Accounts
- Name=Accounts
- SubjectContainsWords=invoice
- MoveToFolder=Deleted Items
- StopProcessingRules=True

This rule targets invoice-themed messages and moves them to Deleted Items. In a BEC investigation, suppression of invoice conversations is high risk because it could conceal payment discussions or prevent the mailbox owner from seeing legitimate correspondence.

The configuration change is confirmed. No affected message or financial activity is available.

### Dot rule that marks and deletes

Parameters:

- Name=.
- DeleteMessage=True
- MarkAsRead=True
- StopProcessingRules=True

No filtering condition appears in the available audit record. The safe conclusion is that the recorded parameters do not show a condition; current Get-InboxRule output would be required to confirm the complete live rule.

The inconspicuous name, read-state modification, deletion action, and stop-processing action make this a high-risk hiding rule.

### Dot rule that moves to Archive

Parameters:

- Name=.
- MoveToFolder=Archive
- MarkAsRead=True
- StopProcessingRules=True

The rule lowers message visibility without deleting the message. No filter condition appears in the available audit record.

This event occurred 5 hours 22 minutes before the two same-destination forwarding rules from the same source IP. The shared tenant, IP, and Stinger identity create a possible association, but the time gap and different sessions prevent the three events from being described as one confirmed login session.

## Forwarding changes

### Single mailbox forwarding to bla@bla[.]com

Set-Mailbox configured:

- ForwardingSmtpAddress=smtp:bla@bla[.]com
- DeliverToMailboxAndForward=True

The mailbox would retain a local copy while forwarding another copy. ResultStatus=True confirms that Exchange accepted the configuration. It does not prove that a later message was received or delivered externally.

### Three-mailbox forwarding cluster

On 2024-03-10, adam@contosomovement.onmicrosoft.com performed three successful Set-Mailbox operations:

| Time UTC | Target Identity | Session relationship |
| --- | --- | --- |
| 21:03:37 | ebd5d4ee-78ef-4404-a3e8-a6784bd128c7 | Separate session and token |
| 21:04:24 | 288fc35b-236b-4b73-868a-11f9d367bb13 | Shared with next event |
| 21:04:43 | 08226516-6d9d-4aef-8dd0-f9a93e8ed646 | Shared with previous event |

All three events share:

- the same actor;
- the same tenant;
- source IP 41.203.78[.]171, with different source ports;
- ForwardingSmtpAddress=johndoe@gmail[.]com;
- DeliverToMailboxAndForward=True;
- a total time span of 66 seconds.

This is the strongest suspicious cluster in the dataset. It supports a conclusion of rapid multi-mailbox forwarding configuration. It does not establish who owned the three target mailboxes or whether messages were exfiltrated.

### Two-account same-destination forwarding

The two ForwardToHeaven rules were created 2 minutes 30 seconds apart:

- adam@contoso.onmicrosoft.com at 05:08:37 UTC;
- stinger@contoso.onmicrosoft.com at 05:11:07 UTC.

They share:

- the same tenant;
- source IP and source port 104.28.196[.]199:28491;
- ForwardTo=alpha@localhost[.]com;
- the same rule name.

The evidence strongly associates the two rule creations as a common simulation activity. It does not establish whether alpha@localhost[.]com was internal, external, deliverable, or only a test placeholder.

## Cross-event correlation notes

### 2023-05-29 pair

The Direct deletion rule and the bla@bla[.]com mailbox-forwarding change occurred 1 minute 16 seconds apart. They share:

- tenant contoso.onmicrosoft.com;
- source IP 104.28.196[.]199, with different source ports;
- the same SessionId;
- target GUID 311b45d6-1a3e-46ac-8434-721367961e19 in the rule object and mailbox forwarding target.

However, the UserId values differ: Stinger created the rule and Matt changed the mailbox. In a production investigation, this inconsistency would require verification against UserKey, directory data, administrative delegation, and the raw audit export. Here it is treated as a strong sample-level association, not proof that one compromised session controlled both identities.

### Reused session identifier across long periods

Some JSON samples reuse the same SessionId across events separated by approximately 15 months. A real authentication session should not be inferred from that reuse. The field is treated as a simulated-data artefact unless supported by corresponding sign-in evidence.

## Rule semantics

Microsoft Exchange documentation supports the following interpretations:

- DeleteMessage=True moves matching messages to Deleted Items; it is not the same as permanent deletion.
- MarkAsRead=True changes message read state.
- MoveToFolder specifies the destination folder.
- StopProcessingRules=True prevents later Inbox rules from processing matching messages.
- ForwardTo forwards messages to the specified recipient.
- DeliverToMailboxAndForward=True retains the message in the original mailbox while also forwarding it.

References:

- [New-InboxRule](https://learn.microsoft.com/en-us/powershell/module/exchangepowershell/new-inboxrule?view=exchange-ps)
- [Set-InboxRule](https://learn.microsoft.com/en-us/powershell/module/exchangepowershell/set-inboxrule?view=exchange-ps)
- [Set-Mailbox](https://learn.microsoft.com/en-us/powershell/module/exchangepowershell/set-mailbox?view=exchange-ps)
- [Add-MailboxPermission](https://learn.microsoft.com/en-us/powershell/module/exchangepowershell/add-mailboxpermission?view=exchange-ps)
- [Add-RecipientPermission](https://learn.microsoft.com/en-us/powershell/module/exchangepowershell/add-recipientpermission?view=exchange-ps)

## Final rule assessment

The 12 records confirm successful configuration changes consistent with mailbox persistence, email hiding, and email forwarding techniques. The behaviour is sufficiently suspicious for high-priority investigation, but authorisation, malicious intent, account compromise, message collection, BEC activity, and financial impact remain unconfirmed.
