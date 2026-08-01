# Recommended Actions

## Response principle

In a live environment, preserve the configuration and surrounding audit evidence before removing it. Validate authorisation quickly, then contain proportionately if the change is unauthorised.

## 1. Validate

### Confirm current Inbox rules

~~~powershell
Get-InboxRule -Mailbox "<mailbox-UPN>" -IncludeHidden |
    Format-List Name,Enabled,Priority,Description,DeleteMessage,MarkAsRead,
    MoveToFolder,ForwardTo,RedirectTo,StopProcessingRules
~~~

Purpose: retrieve visible and hidden Inbox rules and display the conditions and actions relevant to this investigation.

Important parameters:

- -Mailbox selects the mailbox being investigated.
- -IncludeHidden includes rules that normal views may not display.
- Format-List expands the security-relevant rule fields.

### Confirm mailbox-level forwarding

~~~powershell
Get-Mailbox -Identity "<mailbox-UPN>" |
    Format-List DisplayName,PrimarySmtpAddress,ForwardingAddress,
    ForwardingSmtpAddress,DeliverToMailboxAndForward
~~~

Purpose: determine whether Exchange currently forwards mail and whether it retains a local copy.

Important parameter:

- -Identity accepts a unique mailbox identifier such as UPN, email address, alias, or GUID.

### Confirm FullAccess permissions

~~~powershell
Get-MailboxPermission -Identity "<mailbox-UPN>" |
    Where-Object {
        -not $_.IsInherited -and
        $_.User -notlike "NT AUTHORITY\\SELF"
    }
~~~

Purpose: list explicit mailbox permissions while reducing inherited and self-permission noise.

### Confirm SendAs permissions

~~~powershell
Get-RecipientPermission -Identity "<mailbox-UPN>" |
    Where-Object {
        -not $_.IsInherited -and
        $_.Trustee -notlike "NT AUTHORITY\\SELF"
    }
~~~

Purpose: identify explicit SendAs trustees on the target recipient.

## 2. Preserve evidence

Before changing the mailbox:

- export the current rule definitions;
- record forwarding values and delegates;
- retain Unified Audit Log records;
- retain Entra sign-in, MFA, Conditional Access, and device details;
- retain message trace and MailItemsAccessed data;
- capture the related change ticket or confirm that none exists;
- record collection time and timezone;
- map every GUID to a directory object.

Do not rely only on screenshots. Save structured exports where possible.

## 3. Contain if unauthorised

1. Disable or remove malicious rules and forwarding after evidence preservation.
2. Remove unauthorised FullAccess, SendAs, and SendOnBehalf permissions.
3. Revoke active sessions and refresh tokens for affected identities.
4. Reset credentials through the organisation's approved identity-response process.
5. Require MFA re-registration if authentication evidence indicates takeover.
6. Disable the account temporarily when risk cannot be contained safely.
7. Block or restrict external auto-forwarding unless a documented business exception exists.
8. Monitor for recreation of removed rules or permissions.

A password reset alone is insufficient because mailbox rules, delegates, app consent, and active sessions may persist.

## 4. Determine scope and impact

Investigate:

- all rule, forwarding, permission, OAuth, and transport-rule changes by the actor;
- every mailbox modified from the same source IP, device, session, or application;
- sign-ins before and after the configuration event;
- messages received while forwarding or hiding was active;
- message trace to each configured destination;
- SendAs, SendOnBehalf, MailItemsAccessed, soft-delete, and hard-delete operations;
- searches for finance, invoice, password reset, MFA, security alert, and executive correspondence;
- recipients of suspicious internal or external messages;
- payment, bank-detail, supplier, payroll, and invoice changes.

## 5. Recover

- restore legitimate rule and forwarding configuration;
- confirm mailbox owners can see expected messages;
- review Deleted Items, Recoverable Items, Archive, and relevant folders;
- notify affected users and administrators;
- use an out-of-band channel to validate payment or bank-detail changes;
- document every removed permission and rule;
- monitor the mailbox for at least one normal business cycle.

## 6. Detection and prevention

### Detection

- alert on new or changed external forwarding;
- alert on FullAccess, SendAs, and SendOnBehalf changes;
- alert on DeleteMessage, MarkAsRead, Archive, Deleted Items, and StopProcessingRules combinations;
- correlate rapid changes across multiple mailboxes;
- correlate one forwarding destination across multiple accounts;
- raise severity for finance, executive, administrator, and shared mailboxes;
- join Exchange changes with suspicious sign-in, MFA, and Conditional Access evidence.

### Prevention

- disable external forwarding by default;
- require documented exceptions and periodic review;
- use least privilege and dedicated Exchange administration roles;
- require phishing-resistant MFA for administrators where supported;
- review mailbox delegates and forwarding configurations regularly;
- alert mailbox owners through an out-of-band channel when high-risk settings change;
- preserve sufficient audit, sign-in, mailbox-access, and message-trace retention.

## 7. Closure criteria

Close as authorised administration only when:

- the actor, target, time, and exact change match an approved request;
- the mailbox owner or responsible service owner confirms the business need;
- no suspicious surrounding sign-in, message, or mailbox-access activity is found;
- the configuration matches policy.

Escalate as a probable mailbox compromise when:

- the change is unauthorised;
- sign-in evidence supports an unauthorised session;
- the same actor, IP, session, destination, or rule affects additional mailboxes;
- rules hide security or financial messages;
- forwarding reaches an unapproved external recipient;
- SendAs or mailbox access is observed.

Escalate as a BEC incident only when evidence shows fraudulent business communication or manipulation. Record financial impact separately and only when payment or loss evidence exists.

